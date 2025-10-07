
// --- SOCKET.IO REAL-TIME ---
const socket = io();
const room = `chat_${friendId}_${userName}`;
socket.emit('join_room', {room});

const chatBox = document.getElementById('messages');
const input = document.getElementById('text');
const sendBtn = document.getElementById('send');

function addMessage(m) {
    chatBox.appendChild(renderMessage(m));
    chatBox.scrollTop = chatBox.scrollHeight;
}

sendBtn.addEventListener('click', sendMessageHandler);
input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') sendMessageHandler();
});

function sendMessageHandler() {
    const text = input.value.trim();
    if (!text) return;
    socket.emit('send_message', {room, message: text, sender: userName});
    input.value = '';
}

socket.on('receive_message', (m) => {
    addMessage(m);
    if (m.user !== userName) showNotification && showNotification(`${m.user}: ${m.text}`);
});

// Typing indicator
input.addEventListener('input', () => {
    socket.emit('typing', {room, sender: userName});
});

socket.on('user_typing', (data) => {
    let indicator = document.getElementById('typing-indicator');
    if (!indicator) {
        indicator = document.createElement('div');
        indicator.id = 'typing-indicator';
        indicator.className = 'text-muted mb-2';
        indicator.innerText = `${data.user} is typing...`;
        chatBox.appendChild(indicator);
        chatBox.scrollTop = chatBox.scrollHeight;
    }
    clearTimeout(window._typingTimeout);
    window._typingTimeout = setTimeout(() => {
        if (indicator) indicator.remove();
    }, 1500);
});

// Global notification
socket.on('notification', (data) => {
    if (typeof showNotification === 'function') {
        showNotification(data.notification);
    }
});

// Initial load
if (typeof loadHistory === 'function') loadHistory();

// Mark messages as read when window is focused or chat is opened
window.addEventListener('focus', () => {
    socket.emit('mark_read', {room, friend_id: friendId});
});

// Also mark as read after sending a message (to update both sides)
socket.emit('mark_read', {room, friend_id: friendId});

// Listen for real-time read receipts
socket.on('read_receipt', (data) => {
    // Optionally, reload messages or update UI to show read status
    // For now, reload history to update read checkmarks
    if (typeof loadHistory === 'function') loadHistory();
});
