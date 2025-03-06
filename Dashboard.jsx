import React, { useState, useEffect } from 'react';
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { RefreshCw, AlertTriangle, Shield, Activity } from 'lucide-react';

const API_BASE_URL = 'http://localhost:5000';

const DDoSProtectionDashboard = () => {
  const [metrics, setMetrics] = useState({
    total_rps: [],
    response_times: [],
    error_rates: [],
    top_paths: [],
    top_ips: [],
    blocked_ips: []
  });
  
  const [trafficHistory, setTrafficHistory] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(new Date());
  const [activeAlert, setActiveAlert] = useState(false);

  const fetchMetrics = async () => {
    setLoading(true);
    try {
      const [metricsResponse, anomaliesResponse] = await Promise.all([
        fetch(`${API_BASE_URL}/api/metrics`),
        fetch(`${API_BASE_URL}/api/anomalies`)
      ]);
      
      const metricsData = await metricsResponse.json();
      const anomaliesData = await anomaliesResponse.json();
      
      setMetrics(metricsData);
      setAnomalies(anomaliesData);

      // Update traffic history
      const now = new Date();
      const latestData = {
        time: now.toLocaleTimeString(),
        totalRequests: metricsData.total_rps.slice(-1)[0]?.value || 0,
        blockedRequests: metricsData.blocked_ips.length,
        responseTime: metricsData.response_times.slice(-1)[0]?.value || 0,
        errorRate: metricsData.error_rates.slice(-1)[0]?.value || 0
      };
      
      setTrafficHistory(prev => {
        const updated = [...prev, latestData];
        return updated.slice(-10);
      });

      // Trigger alert if any anomalies detected
      setActiveAlert(anomaliesData.length > 0);
      setLastUpdated(now);
    } catch (error) {
      console.error("Error fetching data:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMetrics();
    const intervalId = setInterval(fetchMetrics, 5000);
    return () => clearInterval(intervalId);
  }, []);

  // Prepare data for charts
  const statusData = [
    { name: 'Blocked', value: metrics.blocked_ips.length },
    { name: 'Anomalies', value: anomalies.length },
    { name: 'High Risk', value: metrics.blocked_ips.filter(ip => ip.reason === 'threat_intel').length }
  ];

  const COLORS = ['#FF4842', '#FFC107', '#2196F3'];

  return (
    <div className="flex flex-col w-full h-full bg-gray-50 p-4 overflow-auto">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold text-gray-800">DDoS Protection Dashboard</h1>
        <div className="flex items-center">
          <span className="text-sm text-gray-500 mr-2">
            Last updated: {lastUpdated.toLocaleTimeString()}
          </span>
          <button 
            onClick={fetchMetrics} 
            className="flex items-center px-3 py-1 bg-blue-500 text-white rounded hover:bg-blue-600"
            disabled={loading}
          >
            <RefreshCw size={16} className={`mr-1 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>
      
      {activeAlert && (
        <div className="mb-6 p-4 bg-red-100 border-l-4 border-red-500 flex items-start">
          <AlertTriangle size={24} className="text-red-500 mr-2" />
          <div>
            <h3 className="font-bold text-red-800">Security Alert</h3>
            <p className="text-red-700">
              {anomalies.length} anomalies detected. Potential DDoS activity in progress.
            </p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="bg-white p-4 rounded-lg shadow flex items-center">
          <Shield size={40} className="text-blue-500 mr-4" />
          <div>
            <p className="text-sm text-gray-500">Blocked IPs</p>
            <p className="text-2xl font-bold">{metrics.blocked_ips.length}</p>
          </div>
        </div>
        
        <div className="bg-white p-4 rounded-lg shadow flex items-center">
          <AlertTriangle size={40} className="text-yellow-500 mr-4" />
          <div>
            <p className="text-sm text-gray-500">Active Anomalies</p>
            <p className="text-2xl font-bold">{anomalies.length}</p>
          </div>
        </div>
        
        <div className="bg-white p-4 rounded-lg shadow flex items-center">
          <Activity size={40} className="text-green-500 mr-4" />
          <div>
            <p className="text-sm text-gray-500">Total RPS</p>
            <p className="text-2xl font-bold">
              {metrics.total_rps.slice(-1)[0]?.value || 0}
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <div className="bg-white p-4 rounded-lg shadow">
          <h2 className="text-lg font-semibold mb-4">Traffic Overview</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={trafficHistory}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Line 
                  type="monotone" 
                  dataKey="totalRequests" 
                  stroke="#8884d8" 
                  name="Total Requests" 
                />
                <Line 
                  type="monotone" 
                  dataKey="blockedRequests" 
                  stroke="#ff4d4f" 
                  name="Blocked Requests" 
                />
                <Line 
                  type="monotone" 
                  dataKey="responseTime" 
                  stroke="#52c41a" 
                  name="Response Time (ms)" 
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
        
        <div className="bg-white p-4 rounded-lg shadow">
          <h2 className="text-lg font-semibold mb-4">Security Status</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={statusData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                >
                  {statusData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <div className="bg-white p-4 rounded-lg shadow">
          <h2 className="text-lg font-semibold mb-4">Top Endpoints</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={metrics.top_paths}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="path" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="requests" fill="#2196F3" name="Requests" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        
        <div className="bg-white p-4 rounded-lg shadow">
          <h2 className="text-lg font-semibold mb-4">Top IPs</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={metrics.top_ips}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="ip" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="requests" fill="#FF9800" name="Requests" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="bg-white p-4 rounded-lg shadow">
        <h2 className="text-lg font-semibold mb-4">Blocked IPs</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {metrics.blocked_ips.map((ip, index) => (
            <div key={index} className="p-3 bg-red-50 rounded border border-red-200">
              <div className="font-mono text-red-600">{ip.ip}</div>
              <div className="text-sm text-red-500">{ip.reason}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default DDoSProtectionDashboard;