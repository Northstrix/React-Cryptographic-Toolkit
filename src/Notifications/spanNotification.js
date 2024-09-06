export function showDisappearingSpanNotification(message, displayTime, isError = false) {
    const container = document.getElementById('notification-container');
    const notification = document.createElement('div');
    notification.classList.add('notification-toast');
    if (isError) {
        notification.classList.add('error');
    }
    notification.textContent = message;
    container.appendChild(notification);

    setTimeout(() => {
        notification.classList.add('fade-out');
        setTimeout(() => {
            notification.remove();
        }, 500);
    }, displayTime);
}