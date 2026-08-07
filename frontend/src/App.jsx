import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

import MainLayout from "./layouts/MainLayout";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Inbox from "./pages/Inbox";
import EmailDetails from "./pages/EmailDetails";
import Settings from "./pages/Settings";
import About from "./pages/About";
import Documentation from "./pages/Documentation";

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Login />} />
        
        <Route path="/dashboard" element={<MainLayout><Dashboard /></MainLayout>} />
        <Route path="/inbox" element={<MainLayout><Inbox /></MainLayout>} />
        <Route path="/email/:id" element={<MainLayout><EmailDetails /></MainLayout>} />
        <Route path="/settings" element={<MainLayout><Settings /></MainLayout>} />
        <Route path="/about" element={<MainLayout><About /></MainLayout>} />
        <Route path="/documentation" element={<MainLayout><Documentation /></MainLayout>} />
        
        {/* Redirect old routes or unknowns to dashboard */}
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
      
      <ToastContainer
        position="top-right"
        autoClose={3500}
        hideProgressBar={false}
        newestOnTop
        closeOnClick
        pauseOnHover
        draggable
        theme="dark"
      />
    </BrowserRouter>
  );
}

export default App;
