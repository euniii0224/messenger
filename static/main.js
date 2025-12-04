// flask-messenger/static/main.js

// 1. SocketIO 클라이언트 연결
const socket = io()

// 전역 변수 SENDER, RECIPIENT는 message.html에서 설정됨

// Enter 키 및 버튼 이벤트 리스너 추가
document.addEventListener('DOMContentLoaded', () => {
  const input = document.getElementById('message-input')
  if (input) {
    input.addEventListener('keypress', function (e) {
      if (e.key === 'Enter') {
        sendMessage()
      }
    })
  }
})

// 2. SocketIO 이벤트 처리
socket.on('connect', function () {
  console.log(`SocketIO 연결 성공. 사용자 ${SENDER} 등록 시도...`)
  // 서버에 자신의 사용자 이름(Room)을 등록 요청
  socket.emit('register_user', { username: SENDER })
})

socket.on('status_update', function (data) {
  console.warn(`[STATUS] ${data.msg}`)
})

// 3. 메시지 전송 (SocketIO 이벤트 사용)
function sendMessage() {
  const inputElement = document.getElementById('message-input')
  const message = inputElement.value.trim()

  if (message === '') {
    alert('메시지를 입력해주세요.')
    return
  }

  // 서버의 'send_message' 이벤트로 평문(Plaintext) 전송
  socket.emit('send_message', {
    sender: SENDER,
    recipient: RECIPIENT,
    message: message,
  })

  inputElement.value = ''
}

// 4. 송신 성공 알림 (내가 보낸 메시지가 서버에서 암호화/복호화 시뮬레이션 완료 후 받음)
socket.on('send_success', function (result) {
  // 1. 채팅창에 내가 보낸 메시지 표시
  displayMessage(result.original_message, SENDER)

  // 2. 상세 결과 영역 업데이트 (암호문과 복호화 상태를 화면에 표시)
  updateResultDetail(result)
})

// 5. 새 메시지 수신 (상대방이 보낸 암호문)
socket.on('new_message', function (payload) {
  console.log(
    '상대방으로부터 암호문 수신. 서버 로그에서 복호화 결과를 확인하세요.'
  )

  // 수신자에게 메시지 도착 알림 표시 (복호화는 서버에서 시뮬레이션하고 로그에 남김)
  displayMessage(
    `[${payload.sender} 수신] 서버 콘솔에서 복호화 확인.`,
    payload.sender
  )
})

/**
 * 채팅 박스에 메시지를 시각적으로 표시하는 함수
 */
function displayMessage(text, type) {
  const chatBox = document.getElementById('chat-box')
  const messageDiv = document.createElement('div')

  const className = type === SENDER ? 'sent' : 'received'

  messageDiv.classList.add('message', className)
  messageDiv.innerHTML = `<strong>${type}:</strong> ${text}`

  chatBox.appendChild(messageDiv)
  chatBox.scrollTop = chatBox.scrollHeight
}

/**
 * 암호화/복호화 시뮬레이션 상세 정보를 화면에 표시하는 함수
 */
function updateResultDetail(result) {
  const detailBox = document.getElementById('result-detail')
  const receiver = SENDER === 'Alice' ? 'Bob' : 'Alice'

  detailBox.innerHTML = `
        <h3>전송 정보 (SocketIO)</h3>
        <p><strong>송신자 (${SENDER}) 원본 메시지:</strong> ${result.original_message}</p>
        <p style="color: red;"><strong>네트워크 전송 데이터 (암호문):</strong> ${result.encrypted_message}</p>
        
        <h3>수신 시뮬레이션 결과 (${receiver})</h3>
        <p><strong>복호화 상태:</strong> ${result.decryption_status}</p>
        <p style="font-style: italic;">(💡 서버 콘솔을 통해 GCM 무결성 검증 및 복호화 과정을 확인하세요.)</p>
    `
}
