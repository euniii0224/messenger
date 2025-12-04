# flask-messenger/app.py

# os.path.join을 사용하여 모듈 파일의 절대 경로를 직접 지정합니다.
import os
import sys
import base64

# --- 경로 설정: ModuleNotFoundError를 완전히 우회 ---
# 현재 파일의 디렉토리를 기준으로 crypto 모듈의 경로를 명시적으로 추가
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CRYPTO_DIR = os.path.join(BASE_DIR, 'crypto')
sys.path.append(CRYPTO_DIR) 

# 이제 모듈을 가져올 때 'crypto' 폴더 안에 있는 파일 이름을 직접 지정합니다.
# 주의: 이 방법은 모듈 이름과 파일 이름이 동일해야 합니다.
try:
    from aes_module import AESCipher
    from rsa_module import RSACipher
except ImportError as e:
    # 혹시 모를 경우를 대비해 경로 문제 디버깅 메시지를 출력합니다.
    print("FATAL ERROR: 암호화 모듈을 로드할 수 없습니다. crypto 폴더와 __init__.py를 확인하세요.")
    print(f"DEBUG PATH: {CRYPTO_DIR}")
    sys.exit(1)


# 나머지 라이브러리 임포트
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room
from cryptography.exceptions import InvalidTag 

# 1. Flask 애플리케이션 및 SocketIO 설정
app = Flask(__name__)
app.secret_key = os.urandom(24) 
socketio = SocketIO(app, cors_allowed_origins="*")

# 2. 임시 저장소 설정
USERS = {}        
SESSION_KEYS = {} 

# --- RSA 키 생성 및 사용자 등록 시뮬레이션 ---
def initialize_users():
    """서버 시작 시 사용자들의 RSA 키 쌍을 생성하고 등록합니다."""
    USERS['Alice'] = RSACipher()
    USERS['Bob'] = RSACipher()
    print("--- 서버 초기화 완료 (Alice, Bob RSA 키 생성) ---")
    
initialize_users()


# --- 라우팅: 메인 페이지 및 키 교환 ---

@app.route('/')
def index():
    """메인 페이지: 사용자 선택"""
    return render_template('index.html', users=USERS.keys())


@app.route('/messenger/<sender>', methods=['GET'])
def messenger(sender):
    """
    메시징 페이지 진입 시: 키 교환 과정을 시뮬레이션하고 AES 세션 키를 설정합니다.
    """
    if sender not in USERS:
        return "사용자 오류", 404

    recipient = 'Bob' if sender == 'Alice' else 'Alice'
    
    # 1. 송신자(Sender)는 통신에 사용할 새로운 AES 키를 생성합니다.
    new_aes_cipher = AESCipher()
    new_aes_key_bytes = new_aes_cipher.get_key_bytes()
    
    # 2. 수신자(Recipient)의 RSA 공개키를 가져옵니다.
    recipient_public_key = USERS[recipient].get_public_key()
    
    try:
        # 3. AES 키를 수신자의 RSA 공개키로 암호화합니다. (Key Exchange)
        encrypted_aes_key_b64 = USERS[sender].encrypt(
            new_aes_key_bytes.decode('latin-1'), recipient_public_key
        )
        
        # 4. 수신자는 암호화된 AES 키를 자신의 RSA 개인키로 복호화합니다.
        decrypted_aes_key_str = USERS[recipient].decrypt(encrypted_aes_key_b64)
        decrypted_aes_key_bytes = decrypted_aes_key_str.encode('latin-1')

        # 5. 복호화된 AES 키가 원본 키와 일치하는지 확인
        if decrypted_aes_key_bytes != new_aes_key_bytes:
             return "키 교환 실패: 복호화된 키가 원본과 일치하지 않습니다.", 500
        
        # 6. 통신 성공: 이 키를 송신자와 수신자 모두의 세션 키로 저장합니다.
        SESSION_KEYS[sender] = new_aes_cipher
        SESSION_KEYS[recipient] = AESCipher(key_bytes=decrypted_aes_key_bytes)
        
        key_snippet = base64.b64encode(new_aes_key_bytes)[:10].decode() + '...'
        print(f"\n🔑 키 교환 성공: {sender} <-> {recipient}. AES 키: {key_snippet}")
        
        return render_template('message.html', 
                               sender=sender, 
                               recipient=recipient,
                               key_exchange_status="성공",
                               session_key_snippet=key_snippet)

    except Exception as e:
        print(f"키 교환 중 오류 발생: {e}")
        return "키 교환 오류 발생. 서버 로그 확인.", 500


# --- SocketIO 이벤트 핸들러: 실시간 통신 ---

@socketio.on('connect')
def handle_connect():
    """클라이언트 연결 시"""
    print(f"클라이언트 연결: {request.sid}")

@socketio.on('register_user')
def handle_register_user(data):
    """클라이언트가 자신의 사용자 이름을 서버에 등록 (SocketIO Room 참여)"""
    username = data.get('username')
    if username in USERS:
        # 소켓을 해당 사용자 이름의 '방'에 참여시킵니다.
        join_room(username)
        print(f"사용자 등록 및 Room 참여: {username} (SID: {request.sid})")
        emit('status_update', {'msg': f'{username}님, 실시간 연결 성공'}, room=request.sid)

@socketio.on('send_message')
def handle_send_message(data):
    """
    1. 송신자로부터 평문 메시지 수신
    2. AES-GCM으로 암호화
    3. 수신자에게 암호문 전송 (실시간 푸시)
    4. 수신자의 복호화 시뮬레이션 및 결과 로그 출력
    """
    sender = data.get('sender')
    recipient = data.get('recipient')
    message = data.get('message') # Plaintext

    if sender not in SESSION_KEYS or recipient not in SESSION_KEYS:
        emit('status_update', {'msg': '오류: 세션 키가 설정되지 않았습니다.'}, room=sender)
        return

    # 1. 암호화 (송신자 측 작업)
    sender_aes_cipher = SESSION_KEYS[sender]
    associated_data = f"{sender} to {recipient}".encode('utf-8')
    try:
        encrypted_message_b64 = sender_aes_cipher.encrypt(message, associated_data=associated_data)
    except Exception as e:
        emit('status_update', {'msg': f'암호화 오류: {e}'}, room=sender)
        return

    print(f"\n[SocketIO 송신: {sender} -> {recipient}]")
    print(f"  원본 메시지: '{message}'")
    print(f"  암호문 (B64): '{encrypted_message_b64}'")

    # 2. 실시간 푸시 (서버 -> 수신자)
    message_payload = {
        'sender': sender,
        'encrypted_data': encrypted_message_b64,
        'associated_data': associated_data.decode('utf-8')
    }
    # 수신자의 방(Room)에 메시지 푸시
    socketio.emit('new_message', message_payload, room=recipient)
    
    # 3. 수신자의 복호화 시뮬레이션 (서버 로그 확인용)
    recipient_aes_cipher = SESSION_KEYS[recipient]
    decrypted_message_status = "" # 복호화 결과 상태를 저장

    try:
        decrypted_message = recipient_aes_cipher.decrypt(encrypted_message_b64, associated_data=associated_data)
        
        print(f"[수신 시뮬레이션: {recipient}]")
        print(f"  복호화 성공: '{decrypted_message}'")
        decrypted_message_status = f"✅ 성공: '{decrypted_message}'"
        
    except InvalidTag:
        print(f"[수신 시뮬레이션: {recipient}] 🚨 GCM Tag 불일치! 데이터 변조 감지.")
        decrypted_message_status = "❌ 실패: 메시지가 변조되었습니다."
    except Exception as e:
        print(f"[수신 시뮬레이션: {recipient}] 복호화 오류: {e}")
        decrypted_message_status = f"❌ 오류 발생: {e}"

    # 4. 송신자에게도 성공했음을 알림 (프론트엔드에서 암호화 상세 정보를 보여주기 위함)
    emit('send_success', 
         {'original_message': message, 
          'encrypted_message': encrypted_message_b64,
          'decryption_status': decrypted_message_status}, 
         room=sender)


# 3. 서버 실행
if __name__ == '__main__':
    socketio.run(app, debug=True)