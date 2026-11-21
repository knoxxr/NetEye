const loginForm = document.getElementById("login-form");
const changeForm = document.getElementById("change-form");

function showError(id, message) {
  const el = document.getElementById(id);
  el.textContent = message;
  el.hidden = !message;
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({}));
  return { ok: response.ok, status: response.status, data };
}

function showChange() {
  loginForm.hidden = true;
  changeForm.hidden = false;
  document.getElementById("current").focus();
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  showError("login-error", "");
  const password = document.getElementById("password").value;
  const result = await postJson("/api/login", {
    username: document.getElementById("username").value,
    password,
  });
  if (!result.ok) {
    showError("login-error", result.data.detail || `Sign-in failed (${result.status})`);
    return;
  }
  if (result.data.must_change_password) {
    document.getElementById("current").value = password;
    showChange();
    return;
  }
  location.replace("/");
});

changeForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  showError("change-error", "");
  const next = document.getElementById("new-password").value;
  if (next !== document.getElementById("confirm-password").value) {
    showError("change-error", "New passwords do not match.");
    return;
  }
  const result = await postJson("/api/password", { current: document.getElementById("current").value, new: next });
  if (!result.ok) {
    showError("change-error", result.data.detail || `Password update failed (${result.status})`);
    return;
  }
  location.replace("/");
});

// Already signed in (e.g. reopened tab): continue to the dashboard, or finish the forced change.
fetch("/api/session").then(async (response) => {
  if (!response.ok) return;
  const session = await response.json();
  if (session.must_change_password) showChange();
  else location.replace("/");
}).catch(() => {});
