// static/js/main.js

document.addEventListener('DOMContentLoaded', function() {

    // --- Registration Form: Role Specific Fields ---
    const roleSelect = document.getElementById('roleSelect');
    const admissionNoGroup = document.getElementById('admissionNoGroup');
    const staffCodeGroup = document.getElementById('staffCodeGroup');

    function toggleRegistrationFields() {
        if (!roleSelect) return; // Only run if roleSelect exists

        if (roleSelect.value === 'student') {
            if (admissionNoGroup) admissionNoGroup.style.display = 'block';
            if (staffCodeGroup) staffCodeGroup.style.display = 'none';
        } else if (roleSelect.value === 'teacher') {
            if (admissionNoGroup) admissionNoGroup.style.display = 'none';
            if (staffCodeGroup) staffCodeGroup.style.display = 'block';
        } else {
            if (admissionNoGroup) admissionNoGroup.style.display = 'none';
            if (staffCodeGroup) staffCodeGroup.style.display = 'none';
        }
    }

    if (roleSelect) {
        toggleRegistrationFields(); // Initial check
        roleSelect.addEventListener('change', toggleRegistrationFields);
    }

    // --- Chat Functionality ---
    // This will be encapsulated in a function to be called from chat.html
    // or automatically if the chat elements are present.
    const chatWindow = document.getElementById('chat-window');
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');
    const usersOnlineList = document.getElementById('users-online-list');
    const teacherSelect = document.getElementById('teacherSelect'); // For student to select teacher

    let socket; // Declare socket globally within this scope if needed by multiple functions
    let currentUsername = ''; // Will be set by initializeChat

    function initializeChat(username) {
        if (!chatWindow || !messageInput || !sendButton) {
            // console.log("Chat elements not found on this page.");
            return;
        }
        currentUsername = username;

        // Connect to Socket.IO server
        // The server URL might need adjustment if not served from the same origin
        socket = io({ autoConnect: false }); // Don't connect immediately
        socket.connect();


        socket.on('connect', () => {
            console.log('Connected to chat server with SID:', socket.id);
            // No need to explicitly join 'general_chat' here if server does it on connect
        });

        socket.on('connect_error', (error) => {
            console.error('Connection Error:', error);
            appendSystemMessage('Error connecting to chat. Please try again later.');
        });

        socket.on('disconnect', () => {
            console.log('Disconnected from chat server.');
            appendSystemMessage('You have been disconnected from the chat.');
        });

        // Listen for incoming messages
        socket.on('receive_message', function(data) {
            appendMessage(data.username, data.message, data.timestamp);
        });

        // Listen for user status updates (online/offline)
        socket.on('user_status', function(data) {
            console.log('User status update:', data);
            updateUsersOnlineList(data.users_online);
            if (data.username !== currentUsername) { // Don't show self connect/disconnect
                 // appendSystemMessage(`${data.username} is now ${data.status}.`);
            }
        });

        // Send message when button is clicked
        sendButton.addEventListener('click', sendMessage);

        // Send message when Enter key is pressed in input field
        messageInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });
    }

    function sendMessage() {
        const message = messageInput.value.trim();
        if (message && socket && socket.connected) {
            let recipient = null;
            if (teacherSelect && teacherSelect.value) {
                recipient = teacherSelect.value; // For specific teacher chat (needs server-side routing)
            }

            socket.emit('send_message', {
                message: message,
                recipient: recipient // Send recipient if selected (currently only for general chat)
            });
            messageInput.value = ''; // Clear input field
        } else if (!socket || !socket.connected) {
            appendSystemMessage("Not connected to chat. Cannot send message.");
        }
    }

    function appendMessage(username, message, timestamp) {
        if (!chatWindow) return;

        const messageContainer = document.createElement('div');
        messageContainer.classList.add('message-container');

        const messageBubble = document.createElement('div');
        messageBubble.classList.add('message-bubble');

        const messageMeta = document.createElement('div');
        messageMeta.classList.add('message-meta');

        const strongUsername = document.createElement('strong');
        strongUsername.textContent = username + ": ";
        
        const spanMessage = document.createElement('span');
        spanMessage.textContent = message;

        messageBubble.appendChild(strongUsername);
        messageBubble.appendChild(spanMessage);

        const smallTimestamp = document.createElement('small');
        if (timestamp) {
            smallTimestamp.textContent = new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        } else {
            smallTimestamp.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        }
        messageMeta.appendChild(smallTimestamp);


        if (username === currentUsername) {
            messageContainer.classList.add('my-message');
        } else {
            messageContainer.classList.add('other-message');
        }

        messageContainer.appendChild(messageBubble);
        messageContainer.appendChild(messageMeta);

        // Prepend to keep new messages at the bottom (due to flex-direction: column-reverse)
        chatWindow.prepend(messageContainer);
        // chatWindow.scrollTop = chatWindow.scrollHeight; // Scroll to bottom (not needed with column-reverse)
    }

    function appendSystemMessage(message) {
        if (!chatWindow) return;
        const p = document.createElement('p');
        p.classList.add('system-message');
        p.textContent = message;
        chatWindow.prepend(p); // Prepend due to column-reverse
    }

    function updateUsersOnlineList(users) {
        if (!usersOnlineList) return;
        usersOnlineList.innerHTML = ''; // Clear existing list
        if (users && users.length > 0) {
            users.forEach(user => {
                const li = document.createElement('li');
                li.classList.add('list-group-item');
                li.textContent = user;
                if (user === currentUsername) {
                    li.textContent += " (You)";
                    li.classList.add('font-weight-bold');
                }
                usersOnlineList.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.classList.add('list-group-item', 'text-muted');
            li.textContent = 'No users online.';
            usersOnlineList.appendChild(li);
        }
    }


    // Expose initializeChat to global scope if needed to be called from HTML script tag
    // This is useful if chat.html dynamically calls it
    window.initializeChat = initializeChat;

    // Automatically initialize chat if on the chat page
    // This checks if the necessary elements exist.
    if (document.getElementById('chat-window') && typeof currentUsernameGlobal !== 'undefined' && currentUsernameGlobal) {
        // Assuming 'currentUsernameGlobal' is set in a script tag in chat.html before main.js
        // Example: <script>const currentUsernameGlobal = "{{ current_user.username }}";</script>
        // initializeChat(currentUsernameGlobal);
        // More robust: chat.html calls initializeChat directly like in the template
    }

}); // End DOMContentLoaded