async function handleForm(formId, endpoint, payloadBuilder, successCallback) {
    const form = document.getElementById(formId);
    if (!form) return;
    
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const payload = payloadBuilder();
        
        try {
            const res = await fetch(`/api/${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            
            if (res.ok) {
                successCallback(data, payload);
            } else {
                alert(data.error || 'Request failed');
            }
        } catch (error) {
            console.error("Network error:", error);
        }
    });
}

document.addEventListener('DOMContentLoaded', () => {
    // Registration Form Logic
    handleForm('registerForm', 'register', 
        () => ({
            firstName: document.getElementById('fn').value,
            lastName: document.getElementById('ln').value,
            username: document.getElementById('un').value,
            email: document.getElementById('em').value,
            password: document.getElementById('pw').value
        }),
        () => window.location.href = 'login.html'
    );

    // Login Form Logic
    handleForm('loginForm', 'login',
        () => ({
            username: document.getElementById('un').value,
            password: document.getElementById('pw').value
        }),
        (data, payload) => {
            sessionStorage.setItem('pendingUser', payload.username);
            window.location.href = 'verify.html';
        }
    );

    // MFA Verification Form Logic
    handleForm('verifyForm', 'verify',
        () => ({
            username: sessionStorage.getItem('pendingUser'),
            code: document.getElementById('code').value
        }),
        (data) => {
            sessionStorage.setItem('token', data.token);
            window.location.href = 'dashboard.html';
        }
    );
});
