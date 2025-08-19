import React, { useState } from "react";

function Login({ onLogin }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [rememberMe, setRememberMe] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    try {
      const response = await fetch("http://localhost:8080/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, remember_me: rememberMe }),
      });
      const data = await response.json();
      if (response.ok) {
        // Store token in localStorage if rememberMe, else sessionStorage
        if (rememberMe) {
          localStorage.setItem("token", data.access_token);
        } else {
          sessionStorage.setItem("token", data.access_token);
        }
        onLogin && onLogin(data.user);
      } else {
        setError(data.detail || "Login failed");
      }
    } catch (err) {
      setError("Network error");
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <h2>Login</h2>
      {error && <div style={{ color: "red" }}>{error}</div>}
      <div>
        <input
          type="email"
          placeholder="Email"
          value={email}
          required
          onChange={e => setEmail(e.target.value)}
        />
      </div>
      <div>
        <input
          type="password"
          placeholder="Password"
          value={password}
          required
          onChange={e => setPassword(e.target.value)}
        />
      </div>
      <div className="flex items-center mb-4">
        <input
          id="rememberMe"
          type="checkbox"
          checked={rememberMe}
          onChange={e => setRememberMe(e.target.checked)}
          className="form-checkbox h-4 w-4 text-gold transition duration-150"
         />
         <label htmlFor="rememberMe" className="ml-2 text-sm text-gold">
           Remember Me
         </label>
      </div>
      <button type="submit">Login</button>
    </form>
  );
}

export default Login;
// This code defines a simple login form component in React.
// It handles user input for email and password, allows the user to choose whether to remember their login,
// and submits the login request to a backend API.
// If the login is successful, it stores the authentication token in either localStorage or sessionStorage based on the user's choice.
// It also displays any errors that occur during the login process.
// The component uses React hooks for state management and handles form submission with an asynchronous function.