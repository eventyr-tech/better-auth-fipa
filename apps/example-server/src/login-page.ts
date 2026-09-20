import { randomBytes } from "node:crypto";

/** A small same-origin host login page used by the SDK's system-browser handoff. */
export function loginPage(origin: string): Response {
  const nonce = randomBytes(24).toString("base64");
  return new Response(
    `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Example sign in</title>
<body><main><h1>Sign in to the device example</h1><form id="login">
<label>Email <input id="email" type="email" autocomplete="username" required></label>
<label>Password <input id="password" type="password" autocomplete="current-password" required></label>
<button id="submit">Sign in</button></form><form id="mfa" hidden><label>Verification code <input id="code" inputmode="numeric" autocomplete="one-time-code" required></label><button id="verify">Verify code</button></form><p id="status" role="status"></p></main>
<script nonce="${nonce}">
const form = document.getElementById('login');
const status = document.getElementById('status');
const button = document.getElementById('submit');
const callback = new URL('/api/auth/first-party/browser/complete', location.origin).href;
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  button.disabled = true;
  status.textContent = 'Signing in…';
  const password = document.getElementById('password');
  const body = JSON.stringify({email: document.getElementById('email').value, password: password.value});
  password.value = '';
  try {
    const response = await fetch('/api/auth/sign-in/email', {method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json'}, body});
    const result = await response.json();
    if (!response.ok) throw new Error('Sign in failed');
    if (result.twoFactorRedirect) {
      const sent = await fetch('/api/auth/two-factor/send-otp', {method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json'}, body:'{}'});
      if (!sent.ok) throw new Error('Unable to send code');
      form.hidden = true;
      document.getElementById('mfa').hidden = false;
      status.textContent = 'Enter the verification code from your test operator.';
      return;
    }
    if (!result.user) throw new Error('Sign in failed');
    location.replace(callback);
  } catch {
    status.textContent = 'Unable to sign in. Check your credentials or return to the app to start again.';
    button.disabled = false;
  }
});
document.getElementById('mfa').addEventListener('submit', async (event) => {
  event.preventDefault();
  const verify = document.getElementById('verify');
  verify.disabled = true;
  const input = document.getElementById('code');
  const code = input.value;
  input.value = '';
  try {
    const response = await fetch('/api/auth/two-factor/verify-otp', {method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json'}, body:JSON.stringify({code})});
    const result = await response.json();
    if (!response.ok || !result.user) throw new Error('Verification failed');
    location.replace(callback);
  } catch {
    status.textContent = 'Verification failed. Check the code and try again.';
    verify.disabled = false;
  }
});
</script></body></html>`,
    {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": `default-src 'none'; script-src 'nonce-${nonce}'; connect-src ${origin}; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`,
      },
    },
  );
}
