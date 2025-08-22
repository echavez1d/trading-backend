import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import './App.css';

const API_BASE_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

// Configure axios defaults
axios.defaults.baseURL = API_BASE_URL;

// Auth context
const AuthContext = React.createContext();

// Components
const Header = ({ user, onLogout, onSwitchMode, tradingMode }) => (
  <header className="premium-header">
    <div className="max-w-7xl mx-auto px-6 lg:px-8">
      <div className="flex justify-between items-center py-6">
        <div className="flex items-center space-x-6">
          <div className="brand-logo">
            <h1 className="text-3xl font-bold text-white tracking-wide">
              <span className="text-gold">Σ</span> INVESTORPRO
            </h1>
            <div className="brand-tagline">Elite Trading Platform</div>
          </div>
          {user && (
            <div className="trading-mode-indicator">
              <span className={`mode-badge ${tradingMode === 'paper' ? 'paper' : 'live'}`}>
                {tradingMode === 'paper' ? '🧪 SIMULATION MODE' : '💰 LIVE TRADING'}
              </span>
            </div>
          )}
        </div>
        {user && (
          <div className="user-controls">
            <span className="user-greeting">Welcome, {user.full_name}</span>
            <button
              onClick={onSwitchMode}
              className={`mode-switch-btn ${tradingMode === 'paper' ? 'to-live' : 'to-paper'}`}
            >
              Switch to {tradingMode === 'paper' ? 'Live' : 'Simulation'}
            </button>
            <button onClick={onLogout} className="logout-btn">
              Sign Out
            </button>
          </div>
        )}
      </div>
    </div>
  </header>

);

const LoginForm = ({ onLogin, onSwitchToRegister }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await axios.post('/api/auth/login', { email, password });
      onLogin(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <div className="brand-logo-auth">
            <span className="text-gold text-4xl">Σ</span>
            <h2 className="auth-title">INVESTORPRO</h2>
          </div>
          <p className="auth-subtitle">Elite Trading Platform</p>
        </div>
        
        <form className="auth-form" onSubmit={handleSubmit}>
          {error && (
            <div className="error-alert">
              <span className="error-icon">⚠</span>
              {error}
            </div>
          )}
          
          <div className="form-group">
            <label className="form-label">Email Address</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="form-input"
              required
            />
          </div>
          
          <div className="form-group">
            <label className="form-label">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="form-input"
              required
            />
          </div>
          
          <button
            type="submit"
            disabled={loading}
            className="auth-submit-btn"
          >
            {loading ? 'Authenticating...' : 'Sign In'}
          </button>
          
          <div className="auth-switch">
            <button
              type="button"
              onClick={onSwitchToRegister}
              className="switch-link"
            >
              Create Account
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

const RegisterForm = ({ onRegister, onSwitchToLogin }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await axios.post('/api/auth/register', {
        email,
        password,
        full_name: fullName
      });
      onRegister(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <div className="brand-logo-auth">
            <span className="text-gold text-4xl">Σ</span>
            <h2 className="auth-title">JOIN INVESTORPRO</h2>
          </div>
          <p className="auth-subtitle">Elite Trading Platform</p>
        </div>
        
        <form className="auth-form" onSubmit={handleSubmit}>
          {error && (
            <div className="error-alert">
              <span className="error-icon">⚠</span>
              {error}
            </div>
          )}
          
          <div className="form-group">
            <label className="form-label">Full Name</label>
            <input
              type="text"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              className="form-input"
              required
            />
          </div>
          
          <div className="form-group">
            <label className="form-label">Email Address</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="form-input"
              required
            />
          </div>
          
          <div className="form-group">
            <label className="form-label">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="form-input"
              required
            />
          </div>
          
          <button
            type="submit"
            disabled={loading}
            className="auth-submit-btn"
          >
            {loading ? 'Creating Account...' : 'Create Account'}
          </button>
          
          <div className="auth-switch">
            <button
              type="button"
              onClick={onSwitchToLogin}
              className="switch-link"
            >
              Sign In Instead
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

const TradingInterface = ({ user, tradingMode, onNotification, fetchAccountInfo }) => {
  const [accountInfo, setAccountInfo] = useState(null);
  const [positions, setPositions] = useState([]);
  const [orders, setOrders] = useState([]);
  const [orderForm, setOrderForm] = useState({
    symbol: '',
    quantity: '',
    side: 'buy',
    order_type: 'market',
    limit_price: ''
  });
  const [loading, setLoading] = useState(false);
  const [symbolValidation, setSymbolValidation] = useState({ valid: true, message: '' });
  const [symbolValidating, setSymbolValidating] = useState(false);


 useEffect(() => {
   fetchAccountInfo();
   fetchPositions();
   fetchOrders();
 }, [tradingMode, fetchAccountInfo, fetchPositions, fetchOrders]);


  // Validate symbol when it changes
  useEffect(() => {
    const validateSymbol = async () => {
      if (!orderForm.symbol || orderForm.symbol.length < 1) {
        setSymbolValidation({ valid: true, message: '' });
        return;
      }


      setSymbolValidating(true);
      try {
        const token = localStorage.getItem('token');
        const response = await axios.get(`/api/trading/validate-symbol/${orderForm.symbol}`, {
          headers: { Authorization: `Bearer ${token}` }
        });
       
        setSymbolValidation({
          valid: response.data.tradable,
          message: response.data.message
        });
      } catch (error) {
        setSymbolValidation({
          valid: false,
          message: 'Unable to validate symbol'
        });
      } finally {
        setSymbolValidating(false);
      }
    };


    const timeoutId = setTimeout(validateSymbol, 500); // Debounce validation
    return () => clearTimeout(timeoutId);
  }, [orderForm.symbol]);


  const fetchAccountInfo = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('/api/trading/account', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setAccountInfo(response.data);
    } catch (error) {
      console.error('Error fetching account info:', error);
      if (onNotification) {
        onNotification('Unable to fetch account information. Please check your API keys.', 'error');
      }
    }
  };

  const fetchPositions = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('/api/trading/positions', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setPositions(response.data);
    } catch (error) {
      console.error('Error fetching positions:', error);
    }
  };

  const fetchOrders = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('/api/trading/orders', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setOrders(response.data.orders || []);
    } catch (error) {
      console.error('Error fetching orders:', error);
    }
  };



  const handlePlaceOrder = async (e) => {
    e.preventDefault();
    setLoading(true);

    // Frontend validation
    if (orderForm.order_type === 'limit' && (!orderForm.limit_price || parseFloat(orderForm.limit_price) <= 0)) {
      if (onNotification) {
        onNotification('Limit price is required for limit orders and must be greater than 0', 'error');
      }
      setLoading(false);
      return;
    }

    if (!symbolValidation.valid) {
      if (onNotification) {
        onNotification(`${symbolValidation.message}`, 'error');
      }
      setLoading(false);
      return;
    }

    if (tradingMode === 'live') {
      const orderTypeText = orderForm.order_type === 'limit' ? 
        `${orderForm.order_type.toUpperCase()} order at $${orderForm.limit_price}` : 
        `${orderForm.order_type.toUpperCase()} order`;
        
      const confirmed = window.confirm(
        `⚠️ LIVE TRADING CONFIRMATION\n\nYou are about to place a ${orderForm.side.toUpperCase()} ${orderTypeText} for ${orderForm.quantity} shares of ${orderForm.symbol.toUpperCase()} using REAL MONEY.\n\nThis action cannot be undone. Continue?`
      );
      if (!confirmed) {
        setLoading(false);
        return;
      }
    }

    try {
      const token = localStorage.getItem('token');
      const orderData = {
        symbol: orderForm.symbol.toUpperCase(),
        quantity: parseFloat(orderForm.quantity),
        side: orderForm.side,
        order_type: orderForm.order_type
      };

      if (orderForm.order_type === 'limit') {
        orderData.limit_price = parseFloat(orderForm.limit_price);
      }

      const response = await axios.post('/api/trading/orders', orderData, {
        headers: { Authorization: `Bearer ${token}` }
      });

      // Reset form and refresh data
      setOrderForm({ 
        symbol: '', 
        quantity: '', 
        side: 'buy', 
        order_type: 'market',
        limit_price: '' 
      });
      fetchAccountInfo();
      fetchPositions();
      fetchOrders();
      
      if (onNotification) {
        const orderDetails = response.data.order_type === 'limit' ? 
          `${orderData.side.toUpperCase()} ${orderData.quantity} ${orderData.symbol} at $${orderData.limit_price}` :
          `${orderData.side.toUpperCase()} ${orderData.quantity} ${orderData.symbol} at market price`;
        onNotification(`Order placed successfully: ${orderDetails}`, 'success');
      }
    } catch (error) {
      const errorMessage = error.response?.data?.detail || error.message;
      if (onNotification) {
        onNotification(`Order failed: ${errorMessage}`, 'error');
      }
    } finally {
      setLoading(false);
    }
  };

  const isOrderFormValid = () => {
    return accountInfo && 
           symbolValidation.valid && 
           orderForm.symbol && 
           orderForm.quantity && 
           (orderForm.order_type === 'market' || (orderForm.order_type === 'limit' && orderForm.limit_price));
  };

  return (
    <div className="trading-interface">
      {/* Account Overview */}
      <div className="account-overview">
        <div className="glass-panel">
          <h3 className="panel-title">Account Overview</h3>
          {accountInfo ? (
            <div className="account-stats">
              <div className="stat-item">
                <span className="stat-label">Portfolio Value</span>
                <span className="stat-value">${accountInfo.portfolio_value?.toLocaleString()}</span>
              </div>
              <div className="stat-item">
                <span className="stat-label">Buying Power</span>
                <span className="stat-value text-green">${accountInfo.buying_power?.toLocaleString()}</span>
              </div>
              <div className="stat-item">
                <span className="stat-label">Cash</span>
                <span className="stat-value">${accountInfo.cash?.toLocaleString()}</span>
              </div>
              <div className="stat-item">
                <span className="stat-label">Day Trades</span>
                <span className="stat-value">{accountInfo.day_trade_count}/3</span>
              </div>
            </div>
          ) : (
            <div className="loading-state">
              <div className="loading-spinner"></div>
              <p>Configure Alpaca API keys to enable trading</p>
            </div>
          )}
        </div>
      </div>

      {/* Order Form */}
      <div className="order-section">
        <div className="glass-panel">
          <h3 className="panel-title">Place Order</h3>
          <form onSubmit={handlePlaceOrder} className="order-form">
            <div className="form-row">
              <div className="form-group">
                <label className="form-label">Symbol</label>
                <div className="symbol-input-container">
                  <input
                    type="text"
                    value={orderForm.symbol}
                    onChange={(e) => setOrderForm({...orderForm, symbol: e.target.value.toUpperCase()})}
                    className={`form-input ${!symbolValidation.valid && orderForm.symbol ? 'error' : ''}`}
                    placeholder="AAPL"
                    required
                  />
                  {symbolValidating && <div className="symbol-validating">Validating...</div>}
                </div>
                {orderForm.symbol && !symbolValidation.valid && (
                  <div className="validation-message error">
                    {symbolValidation.message}
                  </div>
                )}
                {orderForm.symbol && symbolValidation.valid && symbolValidation.message && (
                  <div className="validation-message success">
                    ✓ Symbol is tradable
                  </div>
                )}
              </div>
              <div className="form-group">
                <label className="form-label">Quantity</label>
                <input
                  type="number"
                  value={orderForm.quantity}
                  onChange={(e) => setOrderForm({...orderForm, quantity: e.target.value})}
                  className="form-input"
                  placeholder="100"
                  min="1"
                  required
                />
              </div>
            </div>
            
            <div className="form-row">
              <div className="form-group">
                <label className="form-label">Side</label>
                <select
                  value={orderForm.side}
                  onChange={(e) => setOrderForm({...orderForm, side: e.target.value})}
                  className="form-select"
                >
                  <option value="buy">Buy</option>
                  <option value="sell">Sell</option>
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Order Type</label>
                <select
                  value={orderForm.order_type}
                  onChange={(e) => setOrderForm({
                    ...orderForm, 
                    order_type: e.target.value,
                    limit_price: e.target.value === 'market' ? '' : orderForm.limit_price
                  })}
                  className="form-select"
                >
                  <option value="market">Market</option>
                  <option value="limit">Limit</option>
                </select>
              </div>
            </div>

            {/* Limit Price Field - Only shown for limit orders */}
            {orderForm.order_type === 'limit' && (
              <div className="form-row">
                <div className="form-group">
                  <label className="form-label">Limit Price ($)</label>
                  <input
                    type="number"
                    step="0.01"
                    value={orderForm.limit_price}
                    onChange={(e) => setOrderForm({...orderForm, limit_price: e.target.value})}
                    className="form-input"
                    placeholder="0.00"
                    min="0.01"
                    required
                  />
                  <div className="form-helper">
                    Set the maximum price you're willing to pay (buy) or minimum price you'll accept (sell)
                  </div>
                </div>
              </div>
            )}
            
            <button
              type="submit"
              disabled={loading || !isOrderFormValid()}
              className={`order-submit-btn ${orderForm.side === 'buy' ? 'buy-btn' : 'sell-btn'}`}
            >
              {loading ? 'Placing Order...' : 
               `${orderForm.side === 'buy' ? 'Buy' : 'Sell'} ${orderForm.symbol || 'Stock'}${
                 orderForm.order_type === 'limit' && orderForm.limit_price ? ` at $${orderForm.limit_price}` : ''
               }`}
            </button>
          </form>
        </div>
      </div>

      {/* Positions */}
      <div className="positions-section">
        <div className="glass-panel">
          <h3 className="panel-title">Current Positions</h3>
          {positions.length > 0 ? (
            <div className="positions-table">
              <div className="table-header">
                <span>Symbol</span>
                <span>Quantity</span>
                <span>Avg Cost</span>
                <span>Market Value</span>
                <span>Unrealized P&L</span>
              </div>
              {positions.map((position, index) => (
                <div key={index} className="table-row">
                  <span className="symbol">{position.symbol}</span>
                  <span>{position.quantity}</span>
                  <span>${position.avg_cost?.toFixed(2)}</span>
                  <span>${position.market_value?.toLocaleString()}</span>
                  <span className={position.unrealized_pnl >= 0 ? 'text-green' : 'text-red'}>
                    ${position.unrealized_pnl?.toFixed(2)}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <p>No positions yet. Place your first trade above.</p>
            </div>
          )}
        </div>
      </div>

      {/* Recent Orders */}
      <div className="orders-section">
        <div className="glass-panel">
          <h3 className="panel-title">Recent Orders</h3>
          {orders.length > 0 ? (
            <div className="orders-table">
              <div className="table-header">
                <span>Symbol</span>
                <span>Side</span>
                <span>Quantity</span>
                <span>Type</span>
                <span>Limit Price</span>
                <span>Status</span>
                <span>Time</span>
              </div>
              {orders.slice(0, 10).map((order, index) => (
                <div key={index} className="table-row">
                  <span className="symbol">{order.symbol}</span>
                  <span className={order.side === 'buy' ? 'text-green' : 'text-red'}>
                    {order.side.toUpperCase()}
                  </span>
                  <span>{order.qty}</span>
                  <span className="order-type">{order.order_type?.toUpperCase()}</span>
                  <span>
                    {order.limit_price ? `$${parseFloat(order.limit_price).toFixed(2)}` : 
                     order.stop_price ? `$${parseFloat(order.stop_price).toFixed(2)}` : '-'}
                  </span>
                  <span className={`status status-${order.status}`}>{order.status}</span>
                  <span>{order.submitted_at ? new Date(order.submitted_at).toLocaleTimeString() : '-'}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <p>No orders yet.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const TradingCharts = ({ user, watchlistSymbols, tradingMode, fetchChartData }) => {
  const [selectedSymbol, setSelectedSymbol] = useState(watchlistSymbols[0] || 'AAPL');
  const [chartData, setChartData] = useState([]);
  const [timeframe, setTimeframe] = useState('1D');
  const [loading, setLoading] = useState(false);
  const [trades, setTrades] = useState([]);

  useEffect(() => {
    if (selectedSymbol) {
      fetchChartData();
      fetchUserTrades();
    }
}, [selectedSymbol, timeframe, user, fetchChartData, fetchUserTrades]);

  const fetchChartData = useCallback(async () => {
    setLoading(true);
    try {
      const mockData = generateMockChartData(selectedSymbol);
      setChartData(mockData);
    } catch (error) {
      console.error('Error fetching chart data:', error);
    } finally {
      setLoading(false);
    }
  }, [selectedSymbol]);

const fetchUserTrades = useCallback(async () => {
  try {
    const token = localStorage.getItem('token');
    const response = await axios.get(`/api/trading/user-trades/${selectedSymbol}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    setTrades(response.data.trades || []);
  } catch (error) {
    console.error('Error fetching trades:', error);
    setTrades([]);
  }
}, [selectedSymbol]);

    useEffect(() => {
    if (selectedSymbol) {
      fetchChartData();
      fetchUserTrades();
    }
  }, [selectedSymbol, timeframe, fetchChartData, fetchUserTrades]);

  const generateMockChartData = (symbol) => {
    // Generate mock OHLC data
    const data = [];
    const basePrice = Math.random() * 100 + 50;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 30);

    for (let i = 0; i < 30; i++) {
      const date = new Date(startDate);
      date.setDate(date.getDate() + i);
      
      const open = basePrice + (Math.random() - 0.5) * 10;
      const variation = Math.random() * 5;
      const high = open + variation;
      const low = open - variation;
      const close = open + (Math.random() - 0.5) * 3;
      
      data.push({
        date: date.toISOString().split('T')[0],
        open: parseFloat(open.toFixed(2)),
        high: parseFloat(high.toFixed(2)),
        low: parseFloat(low.toFixed(2)),
        close: parseFloat(close.toFixed(2)),
        volume: Math.floor(Math.random() * 1000000)
      });
    }
    return data;
  };

  const calculatePnL = () => {
    const buyTrades = trades.filter(t => t.side === 'buy');
    const sellTrades = trades.filter(t => t.side === 'sell');
    
    let totalBought = 0;
    let totalCost = 0;
    let totalSold = 0;
    let totalRevenue = 0;

    buyTrades.forEach(trade => {
      totalBought += trade.quantity;
      totalCost += trade.quantity * trade.price;
    });

    sellTrades.forEach(trade => {
      totalSold += trade.quantity;
      totalRevenue += trade.quantity * trade.price;
    });

    const avgBuyPrice = totalBought > 0 ? totalCost / totalBought : 0;
    const realizedPnL = totalRevenue - (totalSold * avgBuyPrice);
    const currentPosition = totalBought - totalSold;
    
    // Mock current price
    const currentPrice = chartData.length > 0 ? chartData[chartData.length - 1].close : 0;
    const unrealizedPnL = currentPosition > 0 ? (currentPrice - avgBuyPrice) * currentPosition : 0;

    return {
      totalBought,
      totalSold,
      avgBuyPrice,
      currentPosition,
      realizedPnL,
      unrealizedPnL,
      totalPnL: realizedPnL + unrealizedPnL,
      currentPrice
    };
  };

  const pnlStats = calculatePnL();
  const timeframes = ['1D', '1W', '1M', '3M', '1Y'];

  return (
    <div className="trading-charts">
      <div className="charts-header">
        <div className="glass-panel">
          <div className="charts-controls">
            <div className="symbol-selector">
              <label className="form-label">Symbol</label>
              <select
                value={selectedSymbol}
                onChange={(e) => setSelectedSymbol(e.target.value)}
                className="form-select"
              >
                {watchlistSymbols.map(symbol => (
                  <option key={symbol} value={symbol}>{symbol}</option>
                ))}
              </select>
            </div>
            
            <div className="timeframe-selector">
              <label className="form-label">Timeframe</label>
              <div className="timeframe-buttons">
                {timeframes.map(tf => (
                  <button
                    key={tf}
                    onClick={() => setTimeframe(tf)}
                    className={`timeframe-btn ${timeframe === tf ? 'active' : ''}`}
                  >
                    {tf}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="charts-content">
        {/* P&L Summary */}
        <div className="pnl-summary">
          <div className="glass-panel">
            <h3 className="panel-title">📊 Position Summary - {selectedSymbol}</h3>
            <div className="pnl-grid">
              <div className="pnl-item">
                <span className="pnl-label">Current Position</span>
                <span className="pnl-value">{pnlStats.currentPosition} shares</span>
              </div>
              <div className="pnl-item">
                <span className="pnl-label">Avg Entry Price</span>
                <span className="pnl-value">${pnlStats.avgBuyPrice.toFixed(2)}</span>
              </div>
              <div className="pnl-item">
                <span className="pnl-label">Current Price</span>
                <span className="pnl-value">${pnlStats.currentPrice.toFixed(2)}</span>
              </div>
              <div className="pnl-item">
                <span className="pnl-label">Realized P&L</span>
                <span className={`pnl-value ${pnlStats.realizedPnL >= 0 ? 'positive' : 'negative'}`}>
                  ${pnlStats.realizedPnL.toFixed(2)}
                </span>
              </div>
              <div className="pnl-item">
                <span className="pnl-label">Unrealized P&L</span>
                <span className={`pnl-value ${pnlStats.unrealizedPnL >= 0 ? 'positive' : 'negative'}`}>
                  ${pnlStats.unrealizedPnL.toFixed(2)}
                </span>
              </div>
              <div className="pnl-item">
                <span className="pnl-label">Total P&L</span>
                <span className={`pnl-value total ${pnlStats.totalPnL >= 0 ? 'positive' : 'negative'}`}>
                  ${pnlStats.totalPnL.toFixed(2)}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Chart Area */}
        <div className="chart-container">
          <div className="glass-panel">
            <h3 className="panel-title">📈 Price Chart - {selectedSymbol}</h3>
            {loading ? (
              <div className="chart-loading">
                <div className="loading-spinner"></div>
                <p>Loading chart data...</p>
              </div>
            ) : (
              <div className="chart-placeholder">
                <div className="chart-info">
                  <h4>📈 Interactive Chart Coming Soon</h4>
                  <p>Chart integration with TradingView or similar charting library</p>
                  <div className="chart-features">
                    <span>• Candlestick Charts</span>
                    <span>• Technical Indicators</span>
                    <span>• Entry/Exit Points</span>
                    <span>• Volume Analysis</span>
                  </div>
                </div>
                
                {/* Simple price visualization */}
                <div className="simple-chart">
                  {chartData.slice(-7).map((candle, index) => (
                    <div key={index} className="price-bar">
                      <div className="price-info">
                        <span className="date">{candle.date.slice(-5)}</span>
                        <span className={`price ${candle.close > candle.open ? 'up' : 'down'}`}>
                          ${candle.close}
                        </span>
                      </div>
                      <div 
                        className={`bar ${candle.close > candle.open ? 'up' : 'down'}`}
                        style={{ height: `${Math.random() * 100 + 20}px` }}
                      ></div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Trade History */}
        <div className="trade-history">
          <div className="glass-panel">
            <h3 className="panel-title">📋 Trade History - {selectedSymbol}</h3>
            {trades.length > 0 ? (
              <div className="trades-table">
                <div className="table-header">
                  <span>Date</span>
                  <span>Side</span>
                  <span>Quantity</span>
                  <span>Price</span>
                  <span>Total Value</span>
                  <span>Type</span>
                </div>
                {trades.map((trade) => (
                  <div key={trade.id} className="table-row">
                    <span>{trade.date.toLocaleDateString()}</span>
                    <span className={trade.side === 'buy' ? 'text-green' : 'text-red'}>
                      {trade.side.toUpperCase()}
                    </span>
                    <span>{trade.quantity}</span>
                    <span>${trade.price.toFixed(2)}</span>
                    <span>${(trade.quantity * trade.price).toFixed(2)}</span>
                    <span className="trade-type">{trade.type}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-state">
                <p>No trades found for {selectedSymbol}</p>
                <p className="empty-subtitle">Start trading to see your entry and exit points here.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}; 

const NewsCenter = ({ user, fetchNews}) => {
  const [news, setNews] = useState([]);
  const [loading, setLoading] = useState(false);
  const [activeNewsTab, setActiveNewsTab] = useState('market');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('general');

  useEffect(() => {
    fetchNews();
  }, [activeNewsTab, selectedCategory, fetchNews]);

  const fetchNews = useCallback(async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      let endpoint = '/api/news/market';
      let params = {};

      switch (activeNewsTab) {
        case 'market':
          endpoint = '/api/news/market';
          params = { category: selectedCategory };
          break;
        case 'watchlist':
          endpoint = '/api/news/watchlist';
          break;
        case 'search':
          endpoint = '/api/news/search';
          break;
        default:
          break;
      }

      const response = await axios.get(endpoint, {
        headers: { Authorization: `Bearer ${token}` },
        params: params
      });
      
      setNews(response.data.news || []);
    } catch (error) {
      console.error('Error fetching news:', error);
      setNews([]);
    } finally {
      setLoading(false);
    }
  }, [activeNewsTab, selectedCategory]);

    useEffect(() => {
    fetchNews();
  }, [activeNewsTab, selectedCategory, fetchNews]);

  const searchNews = async () => {
    if (!searchQuery.trim()) {
      fetchNews();
      return;
    }

    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await axios.post('/api/news/search', {
        query: searchQuery,
        category: selectedCategory
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      setNews(response.data.news || []);
    } catch (error) {
      console.error('Error searching news:', error);
      setNews([]);
    } finally {
      setLoading(false);
    }
  };

  const formatNewsDate = (timestamp) => {
    return new Date(timestamp * 1000).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const newsTabs = [
    { id: 'market', name: 'Market News', icon: '🌍' },
    { id: 'watchlist', name: 'My Watchlist', icon: '📊' },
    { id: 'search', name: 'Search', icon: '🔍' }
  ];

  const categories = [
    { value: 'general', label: 'General' },
    { value: 'forex', label: 'Forex' },
    { value: 'crypto', label: 'Crypto' },
    { value: 'merger', label: 'Mergers' }
  ];

  return (
    <div className="news-center">
      <div className="glass-panel">
        <h3 className="panel-title">📰 Market News Center</h3>

        {/* News Tabs */}
        <div className="news-tabs">
          {newsTabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveNewsTab(tab.id)}
              className={`news-tab ${activeNewsTab === tab.id ? 'active' : ''}`}
            >
              <span className="tab-icon">{tab.icon}</span>
              <span className="tab-name">{tab.name}</span>
            </button>
          ))}
        </div>

        {/* Search and Filters */}
        <div className="news-controls">
          {activeNewsTab === 'search' && (
            <div className="search-container">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && searchNews()}
                className="search-input"
                placeholder="Search news by keyword, company, or topic..."
              />
              <button onClick={searchNews} className="search-btn">
                Search
              </button>
            </div>
          )}

          {(activeNewsTab === 'market' || activeNewsTab === 'search') && (
            <div className="category-filter">
              <label className="form-label">Category</label>
              <select
                value={selectedCategory}
                onChange={(e) => setSelectedCategory(e.target.value)}
                className="form-select small"
              >
                {categories.map((cat) => (
                  <option key={cat.value} value={cat.value}>
                    {cat.label}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>

        {/* News List */}
        <div className="news-list">
          {loading ? (
            <div className="loading-state">
              <div className="loading-spinner"></div>
              <p>Loading news...</p>
            </div>
          ) : news.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon">📰</div>
              <p>No news found.</p>
              <p className="empty-subtitle">
                {activeNewsTab === 'watchlist' 
                  ? 'Add stocks to your watchlist to see relevant news.'
                  : 'Try a different search or category.'}
              </p>
            </div>
          ) : (
            news.map((article, index) => (
              <div key={index} className="news-item">
                <div className="news-content">
                  <div className="news-header">
                    <h4 className="news-headline">
                      <a 
                        href={article.url} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="news-link"
                      >
                        {article.headline}
                      </a>
                    </h4>
                    <div className="news-meta">
                      <span className="news-source">{article.source}</span>
                      <span className="news-date">{formatNewsDate(article.datetime)}</span>
                    </div>
                  </div>
                  
                  {article.image && (
                    <div className="news-image">
                      <img src={article.image} alt={article.headline} />
                    </div>
                  )}
                  
                  <div className="news-summary">
                    {article.summary}
                  </div>
                  
                  {article.related && article.related.length > 0 && (
                    <div className="related-symbols">
                      <span className="related-label">Related:</span>
                      {article.related.slice(0, 5).map((symbol, idx) => (
                        <span key={idx} className="related-symbol">
                          {symbol}
                        </span>
                      ))}
                    </div>
                  )}

                  {article.primary_symbol && (
                    <div className="related-symbols">
                      <span className="related-label">Stock:</span>
                      <span className="related-symbol primary">
                        {article.primary_symbol}
                      </span>
                    </div>
                  )}

                  {article.sentiment && (
                    <div className="news-sentiment">
                      <span className={`sentiment sentiment-${article.sentiment}`}>
                        {article.sentiment.toUpperCase()}
                      </span>
                    </div>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

const StockSearch = ({ onAddToWatchlist }) => {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);

  const searchStocks = async (searchQuery) => {
    if (searchQuery.length < 1) {
      setResults([]);
      return;
    }

    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('/api/stocks/search', {
        params: { q: searchQuery },
        headers: { Authorization: `Bearer ${token}` }
      });
      setResults(response.data.results || []);
    } catch (error) {
      console.error('Search error:', error);
      setResults([]);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (e) => {
    const value = e.target.value;
    setQuery(value);
    searchStocks(value);
  };

  return (
    <div className="glass-panel">
      <h3 className="panel-title">Stock Search</h3>
      <div className="search-container">
        <input
          type="text"
          value={query}
          onChange={handleSearch}
          placeholder="Search stocks (e.g., AAPL, Tesla)..."
          className="search-input"
        />
        {loading && <div className="search-loading"></div>}
      </div>

      {results.length > 0 && (
        <div className="search-results">
          {results.map((stock, index) => (
            <div key={index} className="search-result-item">
              <div className="stock-info">
                <div className="stock-symbol">{stock.symbol}</div>
                <div className="stock-description">{stock.description}</div>
              </div>
              <button
                onClick={() => onAddToWatchlist(stock.symbol)}
                className="add-to-watchlist-btn"
              >
                Add to Watchlist
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

const NotesManager = ({ user }) => {
  const [notes, setNotes] = useState([]);
  const [showAddForm, setShowAddForm] = useState(false);
  const [editingNote, setEditingNote] = useState(null);
  const [newNote, setNewNote] = useState({
    title: '',
    content: '',
    tags: []
  });
  const [tagInput, setTagInput] = useState('');

  useEffect(() => {
    fetchNotes();
  }, []);

  const fetchNotes = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('/api/notes', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setNotes(response.data);
    } catch (error) {
      console.error('Error fetching notes:', error);
    }
  };

  const createNote = async () => {
    if (!newNote.title.trim() || !newNote.content.trim()) {
      alert('Please provide both title and content for the note.');
      return;
    }

    try {
      const token = localStorage.getItem('token');
      await axios.post('/api/notes', newNote, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      setNewNote({ title: '', content: '', tags: [] });
      setTagInput('');
      setShowAddForm(false);
      fetchNotes();
    } catch (error) {
      console.error('Error creating note:', error);
      alert('Failed to create note');
    }
  };

  const updateNote = async () => {
    if (!editingNote.title.trim() || !editingNote.content.trim()) {
      alert('Please provide both title and content for the note.');
      return;
    }

    try {
      const token = localStorage.getItem('token');
      await axios.put(`/api/notes/${editingNote.id}`, {
        title: editingNote.title,
        content: editingNote.content,
        tags: editingNote.tags
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      setEditingNote(null);
      fetchNotes();
    } catch (error) {
      console.error('Error updating note:', error);
      alert('Failed to update note');
    }
  };

  const deleteNote = async (noteId) => {
    if (!window.confirm('⚠️ Are you sure you want to delete this note? This action cannot be undone.')) {
      return;
    }

    try {
      const token = localStorage.getItem('token');
      await axios.delete(`/api/notes/${noteId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      fetchNotes();
    } catch (error) {
      console.error('Error deleting note:', error);
      alert('Failed to delete note');
    }
  };

  const handleAddTag = (noteObj, setNoteObj) => {
    if (tagInput.trim() && !noteObj.tags.includes(tagInput.trim())) {
      setNoteObj({
        ...noteObj,
        tags: [...noteObj.tags, tagInput.trim()]
      });
      setTagInput('');
    }
  };

  const removeTag = (tagToRemove, noteObj, setNoteObj) => {
    setNoteObj({
      ...noteObj,
      tags: noteObj.tags.filter(tag => tag !== tagToRemove)
    });
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  return (
    <div className="notes-manager">
      <div className="glass-panel">
        <div className="panel-header">
          <h3 className="panel-title">📝 My Trading Notes</h3>
          <button
            onClick={() => setShowAddForm(!showAddForm)}
            className="add-note-btn"
          >
            Add Note
          </button>
        </div>

        {/* Add Note Form */}
        {showAddForm && (
          <div className="note-form">
            <h4 className="form-title">Create New Note</h4>
            <div className="form-group">
              <label className="form-label">Title</label>
              <input
                type="text"
                value={newNote.title}
                onChange={(e) => setNewNote({ ...newNote, title: e.target.value })}
                className="form-input"
                placeholder="Enter note title..."
              />
            </div>
            <div className="form-group">
              <label className="form-label">Content</label>
              <textarea
                value={newNote.content}
                onChange={(e) => setNewNote({ ...newNote, content: e.target.value })}
                className="form-textarea"
                placeholder="Write your trading notes, insights, or reminders..."
                rows="6"
              />
            </div>
            <div className="form-group">
              <label className="form-label">Tags</label>
              <div className="tags-input-container">
                <input
                  type="text"
                  value={tagInput}
                  onChange={(e) => setTagInput(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && (e.preventDefault(), handleAddTag(newNote, setNewNote))}
                  className="form-input"
                  placeholder="Add tags (press Enter)"
                />
                <button
                  type="button"
                  onClick={() => handleAddTag(newNote, setNewNote)}
                  className="add-tag-btn"
                >
                  Add
                </button>
              </div>
              {newNote.tags.length > 0 && (
                <div className="tags-list">
                  {newNote.tags.map((tag, index) => (
                    <span key={index} className="tag">
                      {tag}
                      <button
                        onClick={() => removeTag(tag, newNote, setNewNote)}
                        className="tag-remove"
                      >
                        ×
                      </button>
                    </span>
                  ))}
                </div>
              )}
            </div>
            <div className="form-actions">
              <button onClick={createNote} className="save-btn">
                Save Note
              </button>
              <button onClick={() => setShowAddForm(false)} className="cancel-btn">
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Notes List */}
        <div className="notes-list">
          {notes.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon">📝</div>
              <p>No notes yet.</p>
              <p className="empty-subtitle">Create your first trading note to keep track of insights and reminders.</p>
            </div>
          ) : (
            notes.map((note) => (
              <div key={note.id} className="note-item">
                {editingNote && editingNote.id === note.id ? (
                  // Edit Form
                  <div className="note-edit-form">
                    <div className="form-group">
                      <input
                        type="text"
                        value={editingNote.title}
                        onChange={(e) => setEditingNote({ ...editingNote, title: e.target.value })}
                        className="form-input"
                      />
                    </div>
                    <div className="form-group">
                      <textarea
                        value={editingNote.content}
                        onChange={(e) => setEditingNote({ ...editingNote, content: e.target.value })}
                        className="form-textarea"
                        rows="4"
                      />
                    </div>
                    <div className="form-group">
                      <div className="tags-input-container">
                        <input
                          type="text"
                          value={tagInput}
                          onChange={(e) => setTagInput(e.target.value)}
                          onKeyPress={(e) => e.key === 'Enter' && (e.preventDefault(), handleAddTag(editingNote, setEditingNote))}
                          className="form-input"
                          placeholder="Add tags"
                        />
                        <button
                          type="button"
                          onClick={() => handleAddTag(editingNote, setEditingNote)}
                          className="add-tag-btn"
                        >
                          Add
                        </button>
                      </div>
                      {editingNote.tags.length > 0 && (
                        <div className="tags-list">
                          {editingNote.tags.map((tag, index) => (
                            <span key={index} className="tag">
                              {tag}
                              <button
                                onClick={() => removeTag(tag, editingNote, setEditingNote)}
                                className="tag-remove"
                              >
                                ×
                              </button>
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                    <div className="form-actions">
                      <button onClick={updateNote} className="save-btn">
                        Update
                      </button>
                      <button onClick={() => setEditingNote(null)} className="cancel-btn">
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  // View Mode
                  <div className="note-content">
                    <div className="note-header">
                      <h4 className="note-title">{note.title}</h4>
                      <div className="note-actions">
                        <button
                          onClick={() => setEditingNote(note)}
                          className="edit-note-btn"
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => deleteNote(note.id)}
                          className="delete-note-btn"
                        >
                          Delete
                        </button>
                      </div>
                    </div>
                    <div className="note-text">
                      {note.content}
                    </div>
                    {note.tags.length > 0 && (
                      <div className="note-tags">
                        {note.tags.map((tag, index) => (
                          <span key={index} className="tag readonly">
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}
                    <div className="note-meta">
                      <span>Created: {formatDate(note.created_at)}</span>
                      {note.updated_at !== note.created_at && (
                        <span>Updated: {formatDate(note.updated_at)}</span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

const StockQuote = ({ symbol, onRemove }) => {
  const [quote, setQuote] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchQuote = async () => {
      try {
        const token = localStorage.getItem('token');
        const response = await axios.get(`/api/stocks/quote/${symbol}`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        setQuote(response.data);
        setError('');
      } catch (err) {
        setError('Failed to fetch quote');
      } finally {
        setLoading(false);
      }
    };

    fetchQuote();
    const interval = setInterval(fetchQuote, 30000);
    return () => clearInterval(interval);
  }, [symbol]);

  if (loading) {
    return (
      <div className="glass-panel">
        <div className="loading-skeleton">
          <div className="skeleton-line"></div>
          <div className="skeleton-line"></div>
          <div className="skeleton-line"></div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="glass-panel error-panel">
        <div className="error-content">
          <span>Error loading {symbol}</span>
          <button onClick={() => onRemove(symbol)} className="remove-btn">
            Remove
          </button>
        </div>
      </div>
    );
  }

  if (!quote) return null;

  const isPositive = quote.change >= 0;

  return (
    <div className="glass-panel stock-quote-panel">
      <div className="quote-header">
        <div className="stock-info">
          <h4 className="stock-symbol">{quote.symbol}</h4>
          <p className="company-name">{quote.company_name}</p>
        </div>
        <button onClick={() => onRemove(symbol)} className="remove-btn">
          ✕
        </button>
      </div>
      
      <div className="quote-content">
        <div className="price-section">
          <span className="current-price">${quote.current_price?.toFixed(2)}</span>
          <span className={`price-change ${isPositive ? 'positive' : 'negative'}`}>
            {isPositive ? '+' : ''}{quote.change?.toFixed(2)} ({quote.change_percent?.toFixed(2)}%)
          </span>
        </div>
        
        <div className="quote-details">
          <div className="detail-row">
            <span className="label">High</span>
            <span className="value">${quote.high?.toFixed(2)}</span>
          </div>
          <div className="detail-row">
            <span className="label">Low</span>
            <span className="value">${quote.low?.toFixed(2)}</span>
          </div>
          <div className="detail-row">
            <span className="label">Open</span>
            <span className="value">${quote.open?.toFixed(2)}</span>
          </div>
          <div className="detail-row">
            <span className="label">Prev Close</span>
            <span className="value">${quote.previous_close?.toFixed(2)}</span>
          </div>
        </div>
        
        {quote.market_cap && (
          <div className="market-cap">
            Market Cap: ${(quote.market_cap / 1000000).toFixed(0)}M
          </div>
        )}
      </div>
    </div>
  );
};

const Watchlist = ({ watchlistSymbols, onRemoveFromWatchlist }) => {
  if (watchlistSymbols.length === 0) {
    return (
      <div className="glass-panel empty-watchlist">
        <h3 className="panel-title">Your Watchlist</h3>
        <div className="empty-state">
          <div className="empty-icon">📊</div>
          <p>No stocks in your watchlist yet.</p>
          <p className="empty-subtitle">Search for stocks to start tracking them.</p>
        </div>
      </div>
    );
  }

  return (
    <div>
      <h3 className="section-title">Market Watchlist</h3>
      <div className="watchlist-grid">
        {watchlistSymbols.map((symbol) => (
          <StockQuote
            key={symbol}
            symbol={symbol}
            onRemove={onRemoveFromWatchlist}
          />
        ))}
      </div>
    </div>
  );
};

const APIKeyManager = ({ user, onKeysUpdate }) => {
  const [keys, setKeys] = useState([]);
  const [showAddForm, setShowAddForm] = useState(false);
  const [newKey, setNewKey] = useState({
    provider: 'alpaca',
    api_key: '',
    secret_key: '',
    environment: 'paper'
  });

  useEffect(() => {
    fetchKeys();
  }, []);

  const fetchKeys = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('/api/keys/list', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setKeys(response.data);
    } catch (error) {
      console.error('Error fetching keys:', error);
    }
  };

  const addKey = async () => {
    try {
      const token = localStorage.getItem('token');
      await axios.post('/api/keys/add', newKey, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setNewKey({ provider: 'alpaca', api_key: '', secret_key: '', environment: 'paper' });
      setShowAddForm(false);
      fetchKeys();
      
      // Refresh API status in parent component
      if (onKeysUpdate) {
        onKeysUpdate();
      }
    } catch (error) {
      console.error('Error adding key:', error);
    }
  };

  const deleteKey = async (keyId) => {
    if (!window.confirm('⚠️ Are you sure you want to delete this API key? This action cannot be undone.')) {
      return;
    }

    try {
      const token = localStorage.getItem('token');
      await axios.delete(`/api/keys/${keyId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      fetchKeys();
      
      // Refresh API status in parent component
      if (onKeysUpdate) {
        onKeysUpdate();
      }
    } catch (error) {
      console.error('Error deleting key:', error);
    }
  };

  return (
    <div className="glass-panel">
      <div className="panel-header">
        <h3 className="panel-title">🔐 API Key Management</h3>
        <button
          onClick={() => setShowAddForm(!showAddForm)}
          className="add-key-btn"
        >
          Add API Key
        </button>
      </div>

      {showAddForm && (
        <div className="add-key-form">
          <h4 className="form-title">Add New API Key</h4>
          <div className="form-grid">
            <div className="form-group">
              <label className="form-label">Provider</label>
              <select
                value={newKey.provider}
                onChange={(e) => setNewKey({ ...newKey, provider: e.target.value })}
                className="form-select"
              >
                <option value="alpaca">Alpaca Trading</option>
                <option value="finnhub">Finnhub</option>
                <option value="coingecko">CoinGecko</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">Environment</label>
              <select
                value={newKey.environment}
                onChange={(e) => setNewKey({ ...newKey, environment: e.target.value })}
                className="form-select"
              >
                <option value="paper">Paper/Demo</option>
                <option value="live">Live</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">API Key</label>
              <input
                type="password"
                placeholder="Enter API Key"
                value={newKey.api_key}
                onChange={(e) => setNewKey({ ...newKey, api_key: e.target.value })}
                className="form-input"
              />
            </div>
            {newKey.provider === 'alpaca' && (
              <div className="form-group">
                <label className="form-label">Secret Key</label>
                <input
                  type="password"
                  placeholder="Enter Secret Key"
                  value={newKey.secret_key}
                  onChange={(e) => setNewKey({ ...newKey, secret_key: e.target.value })}
                  className="form-input"
                />
              </div>
            )}
          </div>
          <div className="form-actions">
            <button onClick={addKey} className="save-btn">
              Save Key
            </button>
            <button onClick={() => setShowAddForm(false)} className="cancel-btn">
              Cancel
            </button>
          </div>
        </div>
      )}

      <div className="keys-list">
        {keys.length === 0 ? (
          <div className="empty-state">
            <p>No API keys configured.</p>
            <p className="empty-subtitle">Add your Alpaca keys to start trading.</p>
          </div>
        ) : (
          keys.map((key) => (
            <div key={key.id} className="key-item">
              <div className="key-info">
                <span className="provider-name">{key.provider}</span>
                <span className={`environment-badge ${key.environment}`}>
                  {key.environment}
                </span>
                <div className="key-date">
                  Added: {new Date(key.created_at).toLocaleDateString()}
                </div>
              </div>
              <button
                onClick={() => deleteKey(key.id)}
                className="delete-key-btn"
              >
                Delete
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

const Dashboard = ({ user, tradingMode }) => {
  const [watchlistSymbols, setWatchlistSymbols] = useState(['AAPL', 'GOOGL', 'MSFT', 'TSLA']);
  const [activeTab, setActiveTab] = useState('portfolio');
  const [apiStatus, setApiStatus] = useState({});
  const [availableAccounts, setAvailableAccounts] = useState([]);
  const [notifications, setNotifications] = useState([]);

  useEffect(() => {
    // Fetch API status and available accounts when component mounts
    fetchApiStatus();
    fetchAvailableAccounts();
  }, []);

  const fetchApiStatus = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('/api/auth/me', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setApiStatus(response.data.api_status || {});
    } catch (error) {
      console.error('Error fetching API status:', error);
    }
  };

  const fetchAvailableAccounts = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('/api/auth/available-accounts', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setAvailableAccounts(response.data.available_accounts || []);
    } catch (error) {
      console.error('Error fetching available accounts:', error);
    }
  };

  const addNotification = (message, type = 'info') => {
    const notification = {
      id: Date.now(),
      message,
      type,
      timestamp: new Date()
    };
    setNotifications(prev => [notification, ...prev.slice(0, 4)]); // Keep only 5 notifications
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== notification.id));
    }, 5000);
  };

  const exportTradingData = async (format = 'xlsx') => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('/api/export/trading-data', {
        headers: { Authorization: `Bearer ${token}` },
        params: { format },
        responseType: 'blob'
      });

      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      
      const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
      link.setAttribute('download', `trading_data_${timestamp}.${format}`);
      
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
      addNotification(`Trading data exported successfully as ${format.toUpperCase()}`, 'success');
    } catch (error) {
      console.error('Export error:', error);
      addNotification('Failed to export trading data', 'error');
    }
  };

  const addToWatchlist = (symbol) => {
    if (!watchlistSymbols.includes(symbol)) {
      setWatchlistSymbols([...watchlistSymbols, symbol]);
      addNotification(`${symbol} added to watchlist`, 'success');
    }
  };

  const removeFromWatchlist = (symbol) => {
    setWatchlistSymbols(watchlistSymbols.filter(s => s !== symbol));
    addNotification(`${symbol} removed from watchlist`, 'info');
  };

  const tabs = [
    { id: 'portfolio', name: 'Portfolio & Trading', icon: '💼' },
    { id: 'charts', name: 'Trade Charts', icon: '📈' },
    { id: 'watchlist', name: 'Market Watch', icon: '📊' },
    { id: 'news', name: 'News Center', icon: '📰' },
    { id: 'search', name: 'Stock Search', icon: '🔍' },
    { id: 'notes', name: 'My Notes', icon: '📝' },
    { id: 'keys', name: 'API Settings', icon: '🔐' }
  ];

  return (
    <div className="dashboard-container">
      {/* Notifications */}
      {notifications.length > 0 && (
        <div className="notifications-container">
          {notifications.map((notification) => (
            <div 
              key={notification.id} 
              className={`notification ${notification.type}`}
            >
              <div className="notification-content">
                <span className="notification-message">{notification.message}</span>
                <button 
                  onClick={() => setNotifications(prev => prev.filter(n => n.id !== notification.id))}
                  className="notification-close"
                >
                  ×
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Enhanced API Status Banner */}
      {Object.keys(apiStatus).length > 0 && (
        <div className="api-status-banner">
          <div className="glass-panel mini">
            <div className="status-header">
              <h4 className="status-title">🔗 API Connections</h4>
              <div className="status-actions">
                <button 
                  onClick={() => exportTradingData('xlsx')}
                  className="export-btn"
                  title="Export to Excel"
                >
                  📊 Export Excel
                </button>
                <button 
                  onClick={() => exportTradingData('csv')}
                  className="export-btn"
                  title="Export to CSV"
                >
                  📄 Export CSV
                </button>
              </div>
            </div>
            <div className="status-grid">
              <div className={`status-item ${apiStatus.finnhub ? 'connected' : 'disconnected'}`}>
                <span className="status-dot"></span>
                <span>Market Data</span>
              </div>
              <div className={`status-item ${apiStatus.alpaca_paper ? 'connected' : 'disconnected'}`}>
                <span className="status-dot"></span>
                <span>Paper Trading</span>
              </div>
              <div className={`status-item ${apiStatus.alpaca_live ? 'connected' : 'disconnected'}`}>
                <span className="status-dot"></span>
                <span>Live Trading</span>
              </div>
              <div className={`status-item ${apiStatus.coingecko ? 'connected' : 'disconnected'}`}>
                <span className="status-dot"></span>
                <span>Crypto Data</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Account Switching Panel */}
      {availableAccounts.length > 0 && (
        <div className="account-switching-panel">
          <div className="glass-panel mini">
            <h4 className="panel-title">🔄 Trading Accounts</h4>
            <div className="accounts-grid">
              {availableAccounts.map((account) => (
                <div 
                  key={account.mode}
                  className={`account-card ${account.mode === tradingMode ? 'active' : ''} ${account.valid ? 'valid' : 'invalid'}`}
                >
                  <div className="account-info">
                    <span className="account-icon">{account.icon}</span>
                    <div className="account-details">
                      <span className="account-name">{account.name}</span>
                      <span className="account-description">{account.description}</span>
                      <span className={`account-status ${account.valid ? 'valid' : 'invalid'}`}>
                        {account.valid ? '✅ Ready' : '❌ Not Connected'}
                      </span>
                    </div>
                  </div>
                  {account.valid && account.mode !== tradingMode && (
                    <button 
                      onClick={() => switchTradingMode(account.mode)}
                      className="switch-account-btn"
                    >
                      Switch
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="nav-tabs">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`nav-tab ${activeTab === tab.id ? 'active' : ''}`}
          >
            <span className="tab-icon">{tab.icon}</span>
            <span className="tab-name">{tab.name}</span>
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="tab-content">
        {activeTab === 'portfolio' && (
          <TradingInterface 
            user={user} 
            tradingMode={tradingMode} 
            onNotification={addNotification}
          />
        )}

        {activeTab === 'charts' && (
          <TradingCharts 
            user={user}
            watchlistSymbols={watchlistSymbols}
            tradingMode={tradingMode}
          />
        )}

        {activeTab === 'watchlist' && (
          <Watchlist
            watchlistSymbols={watchlistSymbols}
            onRemoveFromWatchlist={removeFromWatchlist}
          />
        )}

        {activeTab === 'news' && (
          <NewsCenter user={user} />
        )}

        {activeTab === 'search' && (
          <StockSearch onAddToWatchlist={addToWatchlist} />
        )}

        {activeTab === 'notes' && (
          <NotesManager user={user} />
        )}

        {activeTab === 'keys' && (
          <APIKeyManager 
            user={user} 
            onKeysUpdate={() => {
              fetchApiStatus();
              fetchAvailableAccounts();
              addNotification('API keys updated', 'success');
            }}
          />
        )}
      </div>
    </div>
  );

  // Helper function for account switching
  async function switchTradingMode(newMode) {
    if (newMode === 'live') {
      const confirmed = window.confirm(
        '⚠️ WARNING: You are about to switch to LIVE TRADING mode. This will use real money. Are you sure you want to continue?'
      );
      if (!confirmed) return;
    }

    try {
      const token = localStorage.getItem('token');
      const response = await axios.post('/api/auth/switch-trading-mode', {
        trading_mode: newMode
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });

      if (response.data.success) {
        addNotification(response.data.message, 'success');
        // Refresh the page to update trading mode
        window.location.reload();
      }
    } catch (error) {
      addNotification(
        error.response?.data?.detail || 'Failed to switch trading mode', 
        'error'
      );
    }
  }
};

// Main App Component
function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showRegister, setShowRegister] = useState(false);
  const [tradingMode, setTradingMode] = useState('paper');

  useEffect(() => {
    // Check if user is already logged in
    const token = localStorage.getItem('token');
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      fetchUserInfo();
    } else {
      setLoading(false);
    }
  }, []);

  const fetchUserInfo = async () => {
    try {
      const response = await axios.get('/api/auth/me');
      setUser(response.data);
      setTradingMode(response.data.trading_mode || 'paper');
    } catch (error) {
      console.error('Error fetching user info:', error);
      localStorage.removeItem('token');
      delete axios.defaults.headers.common['Authorization'];
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = (authData) => {
    localStorage.setItem('token', authData.access_token);
    axios.defaults.headers.common['Authorization'] = `Bearer ${authData.access_token}`;
    setUser(authData.user);
    setTradingMode(authData.user.trading_mode || 'paper');
  };

  const handleRegister = (authData) => {
    localStorage.setItem('token', authData.access_token);
    axios.defaults.headers.common['Authorization'] = `Bearer ${authData.access_token}`;
    setUser(authData.user);
    setTradingMode(authData.user.trading_mode || 'paper');
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    delete axios.defaults.headers.common['Authorization'];
    setUser(null);
    setTradingMode('paper');
  };

  const handleSwitchTradingMode = async (e) => {
    e.preventDefault();
    e.stopPropagation();
    
    const newMode = tradingMode === 'paper' ? 'live' : 'paper';
    
    console.log('Switching trading mode from', tradingMode, 'to', newMode);
    
    if (newMode === 'live') {
      const confirmed = window.confirm(
        '⚠️ WARNING: You are about to switch to LIVE TRADING mode. This will use real money. Are you sure you want to continue?'
      );
      if (!confirmed) {
        console.log('User cancelled live trading switch');
        return;
      }
    }

    try {
      const token = localStorage.getItem('token');
      console.log('Making API call to switch trading mode...');
      
      const response = await axios.post('/api/auth/switch-trading-mode', {
        trading_mode: newMode
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      console.log('API response:', response.data);
      setTradingMode(newMode);
      
      // Update user state to reflect the change
      setUser(prev => ({ ...prev, trading_mode: newMode }));
      
      alert(`✅ Successfully switched to ${newMode.toUpperCase()} trading mode!`);
    } catch (error) {
      console.error('Error switching trading mode:', error);
      alert(`❌ Failed to switch trading mode: ${error.response?.data?.detail || error.message}`);
    }
  };

  if (loading) {
    return (
      <div className="loading-screen">
        <div className="loading-content">
          <div className="brand-logo-loading">
            <span className="text-gold text-6xl">Σ</span>
            <h1>INVESTORPRO</h1>
          </div>
          <div className="loading-spinner"></div>
        </div>
      </div>
    );
  }

  if (!user) {
    return showRegister ? (
      <RegisterForm
        onRegister={handleRegister}
        onSwitchToLogin={() => setShowRegister(false)}
      />
    ) : (
      <LoginForm
        onLogin={handleLogin}
        onSwitchToRegister={() => setShowRegister(true)}
      />
    );
  }

  return (
    <AuthContext.Provider value={{ user, tradingMode }}>
      <div className="app-container">
        <Header
          user={user}
          onLogout={handleLogout}
          onSwitchMode={handleSwitchTradingMode}
          tradingMode={tradingMode}
        />
        <Dashboard user={user} tradingMode={tradingMode} />
      </div>
    </AuthContext.Provider>
  );
}

export default App;