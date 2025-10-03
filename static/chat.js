// Simple polling for new messages (demo purpose)
function pollMessages(friendId) {
    setInterval(function() {
        fetch(`/chat/${friendId}/messages`)
            .then(response => response.json())
            .then(data => {
                const chatBox = document.getElementById('chat-box');
                chatBox.innerHTML = '';
                data.messages.forEach(msg => {
                    const div = document.createElement('div');
                    div.innerHTML = `<strong>${msg.sender}:</strong> ${msg.content}`;
                    chatBox.appendChild(div);
                });
                chatBox.scrollTop = chatBox.scrollHeight;
            });
    }, 2000);
}

// Auto-scroll on new message
function scrollToBottom() {
    const chatBox = document.getElementById('chat-box');
    chatBox.scrollTop = chatBox.scrollHeight;
}

document.addEventListener('DOMContentLoaded', function() {
    scrollToBottom();
});
