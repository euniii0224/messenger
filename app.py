# app.py — Flask + SocketIO + RSA/AES Messenger (최종 완성본)

import os
import sys
import base64

# --- crypto 폴더 경로 추가 ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CRYPTO_DIR = os.path.join(BASE_DIR, 'crypto')
sys.path.append(CRYPTO_DIR)

# --- 암호화 모듈 가져오기 ---
try:
    from aes_module import AESCipher
    from rsa_module import RSACipher
except ImportError:
    print("FATAL ERROR: crypto 모듈을 불러올 수 없습니다.")
    sys.exit(1)

# --- Flask & SocketIO ---
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room
from cryptography.exceptions import InvalidTag

# 1. Flask + SocketIO 생성
app = Flask(__name__)
app.secret_key = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*")

# 2. 임시 저장소
USERS = {}
SESSION_KEYS = {}

# 3. 서버 시작 시 RSA 키 생성
def initialize_users():
    USERS['Alice'] = RSACipher()
    USERS['Bob'] = RSACipher()
    print("--- 서버 초기화 완료 (Alice, Bob RSA 키 생성) ---")

initialize_users()

# 4. 라우팅
@app.route('/')
def index():
    return render_template('index.html', users=USERS.keys())


@app.route('/messenger/<sender>', methods=['GET'])
def messenger(sender):
    if sender not in USERS:
        return "사용자 오류", 404

    recipient = 'Bob' if sender == 'Alice' else 'Alice'

    # AES 키 생성
    aes_cipher = AESCipher()
    aes_key_bytes = aes_cipher.get_key_bytes()

    # RSA 공개키 취득
    recipient_pub = USERS[recipient].get_public_key()

    try:
        # RSA 로 AES 키 암호화 (송신자 역할)
        encrypted_key = USERS[sender].encrypt(
            aes_key_bytes.decode('latin-1'),
            recipient_pub
        )

        # 수신자 복호화
        decrypted_key = USERS[recipient].decrypt(encrypted_key)
        decrypted_key_bytes = decrypted_key.encode('latin-1')

        if decrypted_key_bytes != aes_key_bytes:
            return "키 교환 실패", 500

        # 세션키 할당
        SESSION_KEYS[sender] = aes_cipher
        SESSION_KEYS[recipient] = AESCipher(key_bytes=decrypted_key_bytes)

        snippet = base64.b64encode(aes_key_bytes)[:10].decode() + "..."
        print(f"🔑 키 교환 성공: {sender} <-> {recipient} (AES 키: {snippet})")

        return render_template(
            'message.html',
            sender=sender,
            recipient=recipient,
            key_exchange_status="성공",
            session_key_snippet=snippet
        )

    except Exception as e:
        print("키 교환 오류:", e)
        return "키 교환 오류 발생", 500

# 5. SocketIO 이벤트

@socketio.on('connect')
def handle_connect():
    print(f"클라이언트 연결: {request.sid}")


@socketio.on('register_user')
def handle_register_user(data):
    username = data.get('username')
    if username in USERS:
        join_room(username)
        print(f"사용자 등록: {username} (SID: {request.sid})")
        emit('status_update', {'msg': f'{username}님 연결됨!'}, room=request.sid)


@socketio.on('send_message')
def handle_send_message(data):
    sender = data.get('sender')
    recipient = data.get('recipient')
    message = data.get('message')

    if sender not in SESSION_KEYS or recipient not in SESSION_KEYS:
        emit('status_update', {'msg': '세션 키 없음'}, room=sender)
        return

    sender_cipher = SESSION_KEYS[sender]
    associated_data = f"{sender} to {recipient}".encode('utf-8')

    # ① AES 암호화
    encrypted_b64 = sender_cipher.encrypt(message, associated_data=associated_data)

    print(f"\n[SocketIO 송신: {sender} -> {recipient}]")
    print(f"  원본 메시지: '{message}'")
    print(f"  암호문 (B64): '{encrypted_b64}'")

    # ② 복호화 시뮬레이션 (여기에서 decrypted_message 생성)
    decrypted_message = None
    recipient_cipher = SESSION_KEYS[recipient]

    try:
        decrypted_message = recipient_cipher.decrypt(
            encrypted_b64,
            associated_data=associated_data
        )
        print(f"[수신 시뮬레이션: {recipient}] 복호화 성공 → '{decrypted_message}'")
        decrypt_status = f"✅ 성공: '{decrypted_message}'"

    except InvalidTag:
        print(f"[수신 시뮬레이션: {recipient}] ❌ GCM TAG 오류")
        decrypt_status = "❌ TAG 오류 - 메시지 변조"

    except Exception as e:
        print(f"[수신 시뮬레이션: {recipient}] 오류: {e}")
        decrypt_status = f"❌ 오류: {e}"

    # ③ 수신자에게 메시지 전달 (복호문 포함!)
    message_payload = {
        'sender': sender,
        'encrypted_data': encrypted_b64,
        'associated_data': associated_data.decode(),
        'decrypted_message': decrypted_message
    }

    socketio.emit('new_message', message_payload, room=recipient)

    # ④ 송신자에게 결과 전달
    emit(
        'send_success',
        {
            'original_message': message,
            'encrypted_message': encrypted_b64,
            'decryption_status': decrypt_status
        },
        room=sender
    )


# 6. 서버 실행
if __name__ == '__main__':
    socketio.run(app, debug=True)
