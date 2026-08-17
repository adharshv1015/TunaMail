import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";

import axios from "axios";

// Configure global defaults so all axios calls use the correct backend port and send cookies
axios.defaults.baseURL = "http://localhost:8000";
axios.defaults.withCredentials = true;

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
