document.addEventListener('DOMContentLoaded', () => {
    const token = sessionStorage.getItem('token');
    const username = sessionStorage.getItem('username');

    // index.html Logic
    const guestSection = document.getElementById('guestSection');
    const userSection = document.getElementById('userSection');
    const welcomeMessage = document.getElementById('welcomeMessage');
    const logoutBtn = document.getElementById('logoutBtn');
    
    if (guestSection && userSection) {
        if (token && username) {
            guestSection.style.display = 'none';
            userSection.style.display = 'block';
            welcomeMessage.textContent = `Hello, ${username}!`;
            
            const sessionDetails = document.getElementById('sessionDetails');
            if (sessionDetails) {
                sessionDetails.textContent = `Session Token: ${token}`;
            }
        } else {
            guestSection.style.display = 'block';
            userSection.style.display = 'none';
        }
    }

    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            sessionStorage.clear();
            window.location.href = 'index.html';
        });
    }

    // register.html Logic
    const registerForm = document.getElementById('registerForm');
    const regError = document.getElementById('regError');
    
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (regError) regError.style.display = 'none';
            
            const pw = document.getElementById('pw').value;
            const pwRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
            
            if (!pwRegex.test(pw)) {
                if (regError) {
                    regError.textContent = 'Password must be at least 8 characters and include an uppercase letter, a lowercase letter, a number, and a special character.';
                    regError.style.display = 'block';
                }
                return;
            }

            const payload = {
                firstName: document.getElementById('fn').value.trim(),
                lastName: document.getElementById('ln').value.trim(),
                username: document.getElementById('un').value.trim(),
                email: document.getElementById('em').value.trim(),
                password: pw
            };

            try {
                const res = await fetch('/api/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();

                if (res.ok) {
                    document.getElementById('regSuccess').style.display = 'block';
                    registerForm.reset();
                    setTimeout(() => { window.location.href = 'login.html'; }, 2000);
                } else {
                    if (regError) {
                        regError.textContent = `Registration failed: ${data.error}`;
                        regError.style.display = 'block';
                    }
                }
            } catch (error) {
                if (regError) {
                    regError.textContent = "A network error occurred.";
                    regError.style.display = 'block';
                }
            }
        });
    }

    // login.html Logic
    const loginForm = document.getElementById('loginForm');
    const verifyForm = document.getElementById('verifyForm');
    const loginContainer = document.getElementById('loginContainer');
    const mfaContainer = document.getElementById('mfaContainer');
    const loginError = document.getElementById('loginError');
    const resendLink = document.getElementById('resendLink');
    
    let activeUsername = '';

    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (loginError) loginError.style.display = 'none';
            
            const un = document.getElementById('un').value.trim();
            const pw = document.getElementById('pw').value;

            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: un, password: pw })
                });
                const data = await res.json();

                if (res.ok) {
                    activeUsername = un;
                    loginContainer.style.display = 'none';
                    mfaContainer.style.display = 'block';
                } else {
                    if (loginError) {
                        loginError.textContent = `Login failed: ${data.error}`;
                        loginError.style.display = 'block';
                    }
                }
            } catch (error) {
                if (loginError) {
                    loginError.textContent = "A network error occurred.";
                    loginError.style.display = 'block';
                }
            }
        });
    }

    if (verifyForm) {
        verifyForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (loginError) loginError.style.display = 'none';
            
            const code = document.getElementById('code').value.trim();

            try {
                const res = await fetch('/api/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: activeUsername, code: code })
                });
                const data = await res.json();

                if (res.ok) {
                    sessionStorage.setItem('token', data.token);
                    sessionStorage.setItem('username', activeUsername);
                    window.location.href = 'index.html';
                } else {
                    if (loginError) {
                        loginError.textContent = data.error; // Explicitly shows the "token expired" message
                        loginError.style.display = 'block';
                    }
                }
            } catch (error) {
                if (loginError) {
                    loginError.textContent = "A network error occurred.";
                    loginError.style.display = 'block';
                }
            }
        });
    }

    if (resendLink) {
        resendLink.addEventListener('click', async (e) => {
            e.preventDefault();
            if (loginError) loginError.style.display = 'none';
            
            try {
                const res = await fetch('/api/resend', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: activeUsername })
                });
                const data = await res.json();

                if (res.ok) {
                    alert("A new 6-digit code has been sent to your email.");
                } else {
                    if (loginError) {
                        loginError.textContent = data.error;
                        loginError.style.display = 'block';
                    }
                }
            } catch (error) {
                if (loginError) {
                    loginError.textContent = "A network error occurred.";
                    loginError.style.display = 'block';
                }
            }
        });
    }
});
