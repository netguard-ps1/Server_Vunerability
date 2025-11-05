import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add token to requests if available
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Authentication
export const login = (email, password) => api.post('/login', { email, password });
export const verifyToken = () => api.get('/verify');

// Interfaces
export const getInterfaces = () => api.get('/interfaces');

// Capture
export const startCapture = (interface_name, ip_only = false) =>
  api.post('/capture/start', { interface: interface_name, ip_only });
export const stopCapture = () => api.post('/capture/stop');
export const getCaptureStatus = () => api.get('/capture/status');

// PCAP
export const listPcapFiles = () => api.get('/pcap/list');
export const downloadPcap = (filename) => {
  // If no filename provided, download current capture
  const url = filename ? `/pcap/download/${filename}` : '/download_pcap';
  return api.get(url, { responseType: 'blob' });
};
export const uploadPcap = (file) => {
  const formData = new FormData();
  formData.append('file', file);
  return api.post('/pcap/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
};
export const analyzePcap = (filename) => api.get(`/pcap/analyze/${filename}`);

// Health check
export const healthCheck = () => api.get('/health');

// Client-Server Management
export const startServer = () => api.post('/server/start');
export const stopServer = () => api.post('/server/stop');
export const getServerStatus = () => api.get('/server/status');
export const getConnectedClients = () => api.get('/server/clients');
export const disconnectClient = (clientId) => api.post(`/server/disconnect/${clientId}`);

// File Management
export const listServerFiles = () => api.get('/server/files');
export const uploadFileToServer = (file) => {
  const formData = new FormData();
  formData.append('file', file);
  return api.post('/server/files/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
};
export const deleteServerFile = (filename) => api.delete(`/server/files/${filename}`);
export const downloadServerFile = (filename) => api.get(`/server/files/${filename}/download`, { responseType: 'blob' });
export const sendFileToClient = (clientId, filename) => api.post('/server/send-file', { client_id: clientId, filename });
export const broadcastMessage = (message) => api.post('/server/broadcast', { message });

export default api;
