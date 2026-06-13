import { useState, useRef, useEffect } from 'react';
import { useLocation, useParams, useNavigate } from 'react-router-dom';
import { 
  MessageSquareCode, 
  X, 
  Send, 
  Cpu, 
  Layers, 
  Sparkles, 
  ShieldCheck, 
  FileText 
} from 'lucide-react';
import apiClient from '../../lib/axios';
import { useAuth } from '../../hooks/useAuth';

interface Message {
  sender: 'user' | 'assistant';
  text: string;
  timestamp: Date;
}

// Inline formatting helper
function parseInlineText(text: string) {
  const parts = text.split(/(\*\*.*?\*\*|`.*?`)/g);
  return parts.map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={i} className="text-emerald-400 font-bold">{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith('`') && part.endsWith('`')) {
      return <code key={i} className="bg-gray-950 border border-gray-850 px-1.5 py-0.5 rounded font-mono text-[10px] text-cyan-400">{part.slice(1, -1)}</code>;
    }
    return part;
  });
}

// Custom Micro-Markdown Renderer
function parseAssistantMessage(text: string) {
  const lines = text.split('\n');
  return lines.map((line, idx) => {
    const trimmed = line.trim();
    if (!trimmed) return <div key={idx} className="h-1.5" />;

    // Headers
    if (trimmed.startsWith('### ')) {
      return (
        <h3 key={idx} className="font-bold text-white text-[11px] border-b border-gray-800 pb-1 mt-3 mb-1 font-mono uppercase tracking-wider">
          {parseInlineText(trimmed.slice(4))}
        </h3>
      );
    }
    if (trimmed.startsWith('## ')) {
      return (
        <h2 key={idx} className="font-bold text-white text-xs border-b border-gray-800 pb-1 mt-3 mb-1">
          {parseInlineText(trimmed.slice(3))}
        </h2>
      );
    }
    if (trimmed.startsWith('# ')) {
      return (
        <h1 key={idx} className="font-black text-white text-sm border-b border-gray-800 pb-1 mt-3 mb-1">
          {parseInlineText(trimmed.slice(2))}
        </h1>
      );
    }

    // List items
    if (trimmed.startsWith('- ') || trimmed.startsWith('* ') || trimmed.startsWith('• ')) {
      return (
        <div key={idx} className="flex gap-1.5 items-start pl-2 text-gray-300 py-0.5">
          <span className="text-emerald-400 shrink-0 select-none">•</span>
          <span>{parseInlineText(trimmed.slice(2))}</span>
        </div>
      );
    }

    return (
      <p key={idx} className="text-gray-300 leading-relaxed py-0.5">
        {parseInlineText(line)}
      </p>
    );
  });
}

const getApiUrl = (path: string) => {
  const hostname = window.location.hostname;
  const base = hostname === 'localhost' ? 'http://localhost:5000/api' : 
               hostname === '127.0.0.1' ? 'http://127.0.0.1:5000/api' : 
               (import.meta.env.VITE_API_URL || 'http://127.0.0.1:5000/api');
  return `${base}${path}`;
};

function AIChatAssistant() {
  const { isAuthenticated } = useAuth();
  const location = useLocation();
  const params = useParams();
  const navigate = useNavigate();

  const [isOpen, setIsOpen] = useState(false);
  
  // Load initial messages from sessionStorage or default to welcome message
  const [messages, setMessages] = useState<Message[]>(() => {
    const saved = sessionStorage.getItem('vtrace_copilot_chat');
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        return parsed.map((m: any) => ({
          ...m,
          timestamp: new Date(m.timestamp)
        }));
      } catch (e) {
        console.error('Failed to parse saved copilot chat', e);
      }
    }
    return [
      {
        sender: 'assistant',
        text: '### Welcome to V-Trace Copilot\n\nI can analyze metadata risk, inspect activity logs, and summarize cases. How can I assist your investigation today?',
        timestamp: new Date()
      }
    ];
  });

  const [inputText, setInputText] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [aiStatus, setAiStatus] = useState({ provider: 'Offline Engine', online: false, model: 'offline' });
  const [suggestedActions, setSuggestedActions] = useState<string[]>([]);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll chat to bottom
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    if (isOpen) {
      scrollToBottom();
    }
  }, [messages, isOpen]);

  // Save messages to sessionStorage whenever they change
  useEffect(() => {
    sessionStorage.setItem('vtrace_copilot_chat', JSON.stringify(messages));
    console.log("Loaded Messages", messages);
  }, [messages]);

  // Fetch active AI Provider status when chat expands
  useEffect(() => {
    if (isAuthenticated && isOpen) {
      apiClient.get<{ provider: string; online: boolean; model: string }>('/ai/status')
        .then(res => {
          if (res.data) {
            setAiStatus(res.data);
          }
        })
        .catch(err => {
          console.error('Failed to fetch AI status', err);
          setAiStatus({ provider: 'Connection Issue', online: false, model: 'offline' });
        });
    }
  }, [isAuthenticated, isOpen]);

  // If user is not authenticated, do not show the assistant
  if (!isAuthenticated) return null;

  // Dynamically resolve contextual IDs from current route parameters
  const getContextIds = () => {
    const isCaseRoute = location.pathname.includes('/cases/');
    const isContentRoute = location.pathname.includes('/content/');

    return {
      caseId: isCaseRoute && params.id ? params.id : undefined,
      evidenceId: isContentRoute && params.id ? params.id : undefined
    };
  };

  const handleSendMessage = async (text: string, promptType?: string) => {
    if (!text.trim() || isSending) return;

    const userMsg: Message = {
      sender: 'user',
      text,
      timestamp: new Date()
    };

    // Format history for backend (limit to last 20 messages to conserve token space & memory)
    const historyPayload = messages.slice(-20).map(m => ({
      role: m.sender === 'user' ? 'user' : 'assistant',
      content: m.text
    }));

    setMessages((prev) => [...prev, userMsg]);
    setInputText('');
    setIsSending(true);
    setSuggestedActions([]);

    const { caseId, evidenceId } = getContextIds();

    try {
      const savedToken = localStorage.getItem('vtrace_access_token');
      const response = await fetch(getApiUrl('/ai/chat'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${savedToken}`
        },
        body: JSON.stringify({
          message: text,
          promptType,
          caseId,
          evidenceId,
          currentRoute: location.pathname,
          history: historyPayload,
          stream: true
        })
      });

      if (!response.ok) {
        throw new Error('Server error');
      }

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      let assistantResponseText = '';

      const assistantPlaceholder: Message = {
        sender: 'assistant',
        text: '',
        timestamp: new Date()
      };
      
      setMessages((prev) => [...prev, assistantPlaceholder]);

      while (reader) {
        const { value, done } = await reader.read();
        if (done) break;

        const chunkStr = decoder.decode(value);
        const lines = chunkStr.split('\n');
        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const dataStr = line.slice(6).trim();
            if (dataStr === '[DONE]') break;
            try {
              const dataObj = JSON.parse(dataStr);
              if (dataObj.chunk) {
                assistantResponseText += dataObj.chunk;
                setMessages((prev) => {
                  const updated = [...prev];
                  if (updated.length > 0) {
                    updated[updated.length - 1] = {
                      ...updated[updated.length - 1],
                      text: assistantResponseText
                    };
                  }
                  return updated;
                });
              }
            } catch (e) {
              // Ignore partial JSON parse errors
            }
          }
        }
      }

      let cleanText = assistantResponseText;

      // Extract actions from reply
      const actionsRegex = /\[ACTIONS:\s*([^\]]+)\]/i;
      const actionsMatch = cleanText.match(actionsRegex);
      if (actionsMatch) {
        const actionsList = actionsMatch[1].split('|').map(a => a.trim());
        setSuggestedActions(actionsList);
        cleanText = cleanText.replace(actionsRegex, '').trim();
      }

      // Detect navigation commands
      const navRegex = /\[NAVIGATE:\s*([^\s\]]+)\]/i;
      const match = cleanText.match(navRegex);
      if (match) {
        let targetRoute = match[1].trim();
        cleanText = cleanText.replace(navRegex, '').trim();

        // Route mapping
        if (targetRoute === '/resume-intel') {
          targetRoute = '/ats';
        } else if (targetRoute === '/plagiarism-check' || targetRoute === '/reports') {
          targetRoute = '/plagiarism';
        } else if (targetRoute === '/activity-history') {
          targetRoute = '/audit';
        } else if (targetRoute === '/evidence-library' || targetRoute === '/evidence') {
          targetRoute = '/content';
        } else if (targetRoute === '/verify') {
          targetRoute = '/content/new';
        }

        navigate(targetRoute);
      }

      setMessages((prev) => {
        const updated = [...prev];
        if (updated.length > 0) {
          updated[updated.length - 1] = {
            ...updated[updated.length - 1],
            text: cleanText
          };
        }
        return updated;
      });

    } catch {
      setAiStatus({ provider: 'Connection Issue', online: false, model: 'offline' });
      // Local recovery fallback: display offline intelligence message instead of any error
      const cleanText = '⚠️ **Using Offline Intelligence Mode**';
      const errorMsg: Message = {
        sender: 'assistant',
        text: cleanText,
        timestamp: new Date()
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setIsSending(false);
    }
  };

  const handleSuggestedActionClick = (action: string) => {
    handleSendMessage(action);
  };

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    handleSendMessage(inputText);
  };

  const quickPrompts = [
    { label: 'Summarize Case', icon: <FileText className="h-3.5 w-3.5" />, type: 'summarize_case', text: 'Provide a complete summary of the currently selected case.' },
    { label: 'Analyze Evidence', icon: <Cpu className="h-3.5 w-3.5" />, type: 'analyze_evidence', text: 'Analyze the currently selected evidence and identify risks.' },
    { label: 'Explain ATS Report', icon: <Layers className="h-3.5 w-3.5" />, type: 'explain_ats', text: 'Explain the latest ATS report and identify key improvement recommendations.' },
    { label: 'Generate Report', icon: <ShieldCheck className="h-3.5 w-3.5" />, type: 'generate_report', text: 'Generate a detailed investigation report including summary, findings, risk assessment, timeline, and recommendations.' }
  ];

  return (
    <div className="fixed bottom-6 right-6 z-50 font-sans">
      {/* Floating Toggle Button */}
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          className="relative flex h-14 w-14 items-center justify-center rounded-full bg-emerald-400 text-gray-900 shadow-xl transition hover:bg-emerald-300 hover:scale-105 active:scale-95"
          aria-label="Open AI Assistant"
        >
          <MessageSquareCode className="h-6 w-6" />
          <span className="absolute -right-0.5 -top-0.5 flex h-3.5 w-3.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-cyan-400 opacity-75" />
            <span className="relative inline-flex h-3.5 w-3.5 rounded-full bg-cyan-500" />
          </span>
        </button>
      )}

      {/* Expanded Chat Box */}
      {isOpen && (
        <div className="flex h-[520px] w-[360px] flex-col overflow-hidden rounded-2xl border border-gray-800 bg-gray-900 shadow-2xl backdrop-blur-md">
          {/* Header */}
          <header className="flex items-center justify-between border-b border-gray-800 bg-gray-950 px-4 py-3.5 text-white">
            <div className="flex items-center gap-2">
              <div className="relative rounded-lg bg-emerald-500/10 p-1.5 border border-emerald-500/20">
                <Sparkles className="h-4 w-4 text-emerald-400" />
              </div>
              <div className="text-left">
                <span className="block text-xs font-bold uppercase tracking-wider text-emerald-400">V-Trace AI Copilot</span>
                <div className="flex items-center gap-1 mt-0.5 select-none">
                  <span className={`h-1.5 w-1.5 rounded-full ${
                    aiStatus.provider === 'Connection Issue' ? 'bg-red-500 shadow-[0_0_8px_#ef4444]' :
                    aiStatus.online ? 'bg-emerald-400 animate-pulse shadow-[0_0_8px_#34d399]' :
                    'bg-amber-400 shadow-[0_0_8px_#fbbf24]'
                  }`} />
                  <span className="text-[9px] font-mono text-gray-400 uppercase tracking-wider">
                    {aiStatus.provider === 'Connection Issue' ? 'Connection Issue' :
                     aiStatus.online ? `${aiStatus.provider} Online` : 'Offline Intelligence'}
                  </span>
                  {aiStatus.online && (
                    <span className="text-[8px] font-mono text-gray-500 ml-1">
                      ({aiStatus.model})
                    </span>
                  )}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => {
                  sessionStorage.removeItem('vtrace_copilot_chat');
                  setMessages([
                    {
                      sender: 'assistant',
                      text: '### Welcome to V-Trace Copilot\n\nI can analyze metadata risk, inspect activity logs, and summarize cases. How can I assist your investigation today?',
                      timestamp: new Date()
                    }
                  ]);
                  setSuggestedActions([]);
                }}
                className="text-[9px] font-mono tracking-wider uppercase border border-gray-800 bg-gray-900 hover:bg-gray-850 text-gray-400 hover:text-emerald-400 px-2 py-1 rounded transition select-none"
                title="Clear Session Chat"
              >
                Clear Chat
              </button>
              <button
                onClick={() => setIsOpen(false)}
                className="rounded-md p-1 text-gray-400 hover:bg-gray-900 hover:text-white"
              >
                <X className="h-4.5 w-4.5" />
              </button>
            </div>
          </header>

          {/* Messages Feed */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 bg-gray-900/40">
            {messages.map((msg, i) => (
              <div
                key={i}
                className={`flex flex-col ${msg.sender === 'user' ? 'items-end' : 'items-start'}`}
              >
                <div
                  className={`max-w-[85%] rounded-xl px-3.5 py-2.5 text-xs leading-relaxed ${
                    msg.sender === 'user'
                      ? 'bg-emerald-400 text-gray-900 font-semibold rounded-tr-none'
                      : 'bg-gray-950/80 border border-gray-850 text-gray-300 rounded-tl-none space-y-2'
                  }`}
                >
                  {msg.sender === 'assistant' ? (
                    parseAssistantMessage(msg.text)
                  ) : (
                    <span>{msg.text}</span>
                  )}
                </div>
                <span className="text-[9px] text-gray-550 mt-1 px-1 font-mono">
                  {msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>
              </div>
            ))}

            {/* Suggested Actions Chips */}
            {!isSending && suggestedActions.length > 0 && (
              <div className="flex flex-wrap gap-1.5 pt-1.5 pl-1 items-start justify-start select-none">
                {suggestedActions.map((action, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => handleSuggestedActionClick(action)}
                    className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 border border-emerald-500/25 px-2.5 py-1 text-[10px] font-semibold text-emerald-400 hover:bg-emerald-500/25 transition hover:scale-[1.02] active:scale-95"
                  >
                    {action}
                  </button>
                ))}
              </div>
            )}

            {isSending && (
              <div className="flex flex-col items-start">
                <div className="rounded-xl rounded-tl-none border border-gray-850 bg-gray-950/80 px-4 py-3 text-xs text-gray-400">
                  <div className="flex items-center gap-1.5">
                    <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-emerald-400 [animation-delay:-0.3s]" />
                    <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-emerald-400 [animation-delay:-0.15s]" />
                    <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-emerald-400" />
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Quick Prompts Panel */}
          <div className="p-2 border-t border-gray-850 bg-gray-950/40 flex gap-1.5 overflow-x-auto whitespace-nowrap scrollbar-none">
            {quickPrompts.map((p) => (
              <button
                key={p.type}
                type="button"
                onClick={() => handleSendMessage(p.text, p.type)}
                disabled={isSending}
                className="inline-flex items-center gap-1 rounded bg-gray-950 border border-gray-850 px-2 py-1 text-[10px] font-semibold text-gray-300 hover:border-emerald-400 hover:text-emerald-300 transition disabled:opacity-50"
              >
                {p.icon}
                <span>{p.label}</span>
              </button>
            ))}
          </div>

          {/* Input Form */}
          <form onSubmit={handleFormSubmit} className="border-t border-gray-850 bg-gray-950 p-2">
            <div className="relative flex items-center">
              <input
                type="text"
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                placeholder="Ask the AI copilot..."
                disabled={isSending}
                className="w-full rounded-lg border border-gray-800 bg-gray-900/60 py-2 pl-3 pr-10 text-xs text-white placeholder-gray-500 outline-none transition focus:border-emerald-500 disabled:opacity-60"
              />
              <button
                type="submit"
                disabled={!inputText.trim() || isSending}
                className="absolute right-1.5 rounded-md p-1.5 text-emerald-400 hover:bg-gray-900 disabled:opacity-40"
              >
                <Send className="h-3.5 w-3.5" />
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}

export default AIChatAssistant;
