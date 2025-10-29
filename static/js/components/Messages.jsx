import React, { useState, useEffect, useRef } from 'react';
import { io } from 'socket.io-client';

const Messages = () => {
  const [messageInput, setMessageInput] = useState('');
  const [isRecording, setIsRecording] = useState(false);
  const [showSendButton, setShowSendButton] = useState(false);
  const [timer, setTimer] = useState('0:00');
  const [messages, setMessages] = useState([]);
  const socket = useRef(null);
  const mediaRecorder = useRef(null);
  const audioChunks = useRef([]);
  const stream = useRef(null);
  const startTime = useRef(null);
  const timerInterval = useRef(null);

  useEffect(() => {
    socket.current = io();

    socket.current.on('connect', () => console.log('Socket.IO Connecté.'));
    socket.current.on('message_history', (data) => setMessages(data.messages));
    socket.current.on('new_message', (message) => setMessages((prev) => [...prev, message]));

    return () => socket.current.disconnect();
  }, []);

  const startRecording = async () => {
    setIsRecording(true);
    setShowSendButton(false);
    audioChunks.current = [];
    startTime.current = Date.now();
    setTimer('0:00');

    try {
      stream.current = await navigator.mediaDevices.getUserMedia({ audio: true });
      mediaRecorder.current = new MediaRecorder(stream.current);
      mediaRecorder.current.ondataavailable = (event) => audioChunks.current.push(event.data);
      mediaRecorder.current.onstop = stopRecording;
      mediaRecorder.current.start();

      timerInterval.current = setInterval(() => {
        const time = Math.floor((Date.now() - startTime.current) / 1000);
        const minutes = Math.floor(time / 60);
        const seconds = time % 60;
        setTimer(`${minutes}:${seconds < 10 ? '0' : ''}${seconds}`);
      }, 1000);
    } catch (error) {
      console.error('Erreur enregistrement:', error);
    }
  };

  const stopRecording = () => {
    if (mediaRecorder.current && mediaRecorder.current.state !== 'inactive') {
      mediaRecorder.current.stop();
    }
    if (stream.current) {
      stream.current.getTracks().forEach(track => track.stop());
    }
    clearInterval(timerInterval.current);

    const audioBlob = new Blob(audioChunks.current, { type: 'audio/wav' });
    const duration = Math.floor((Date.now() - startTime.current) / 1000);

    const formData = new FormData();
    formData.append('audio', audioBlob, 'recording.wav');
    formData.append('duration', duration);

    fetch('/api/chat/send_voice', {
      method: 'POST',
      headers: { 'X-CSRF-TOKEN': window.getCsrfToken() },
      body: formData
    }).then(response => response.json())
      .then(data => {
        if (data.success) {
          const message = { type: 'voice', content: data.file_path, duration };
          socket.current.emit('send_message', { chatroom_id: 'your_chatroom_id', message }); 
        }
      }).catch(error => console.error(error));

    setIsRecording(false);
    setShowSendButton(true);
    setTimer('0:00');
  };

  const handleInputChange = (e) => {
    const text = e.target.value;
    setMessageInput(text);
    setShowSendButton(text.trim() !== '' && !isRecording);
  };

  const sendMessage = () => {
    if (messageInput.trim()) {
      const message = { type: 'text', content: messageInput };
      socket.current.emit('send_message', { chatroom_id: 'your_chatroom_id', message });
      setMessageInput('');
    }
  };

  return (
    <div className="chat-container">
      <div className="messages-display">
        {messages.map((msg, index) => (
          <div key={index} className="message-wrapper">
            {msg.type === 'voice' ? (
              <div>
                <audio controls src={`/uploads/${msg.content}`}></audio>
                <span className="ml-2 text-gray-500">({msg.duration}s)</span>
              </div>
            ) : (
              <p>{msg.content}</p>
            )}
          </div>
        ))}
      </div>
      <div className="message-input-area">
        <input
          type="text"
          value={messageInput}
          onChange={handleInputChange}
          className="flex-1 p-2 border rounded"
          placeholder="Tapez un message..."
        />
        {isRecording ? (
          <React.Fragment>
            <span id="recording-timer">{timer}</span>
            <button onClick={stopRecording} className="ml-2 p-2 bg-red-500 text-white rounded">Stop</button>
          </React.Fragment>
        ) : showSendButton ? (
          <button onClick={sendMessage} className="ml-2 p-2 bg-blue-500 text-white rounded-full">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
              <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"></path>
            </svg>
          </button>
        ) : (
          <button onClick={startRecording} className="ml-2 p-2 bg-gray-500 text-white rounded-full">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 14c1.66 0 3-1.34 3-3V5c0-1.66-1.34-3-3-3S9 3.34 9 5v6c0 1.66 1.34 3 3 3zm5.91-3c-.49 0-.9 .36-.98 .85C16.52 14.2 14.47 16 12 16s-4.52-1.8-4.93-4.15c-.08-.49-.49-.85-.98-.85-.61 0-1.09 .54-1 1.14.49 2.84 2.76 5.16 5.91 5.85V20h-2c-.55 0-1 .45-1 1s.45 1 1 1h6c.55 0 1-.45 1-1s-.45-1-1-1h-2v-2.15c3.15-.69 5.42-3.01 5.91-5.85.1-.6-.39-1.14-1-1.14z"></path>
            </svg>
          </button>
        )}
      </div>
    </div>
  );
};