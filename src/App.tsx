// @ts-nocheck

import React, { useEffect, useMemo, useState } from "react";
import { createClient } from "@supabase/supabase-js";
import {
  KeyRound,
  Lock,
  LogOut,
  Search,
  Send,
  ShieldCheck,
  UserPlus,
} from "lucide-react";
import "./App.css";

const supabase = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_ANON_KEY
);

const PRIVATE_KEY_STORAGE = "secure-message-private-key-v2";
const TEXT = new TextEncoder();
const FROM_TEXT = new TextDecoder();

function bytesToBase64(bytes) {
  let binary = "";
  const arr = new Uint8Array(bytes);

  for (let i = 0; i < arr.length; i++) {
    binary += String.fromCharCode(arr[i]);
  }

  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function shortKey(key) {
  if (!key) return "";
  return `${key.slice(0, 16)}…${key.slice(-12)}`;
}

async function generateIdentity() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    true,
    ["deriveBits"]
  );

  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);

  return {
    publicKey: btoa(JSON.stringify(publicJwk)),
    privateKey: btoa(JSON.stringify(privateJwk)),
  };
}

async function importPrivateKey(privateKeyBase64) {
  const jwk = JSON.parse(atob(privateKeyBase64));

  return crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    false,
    ["deriveBits"]
  );
}

async function importPublicKey(publicKeyBase64) {
  const jwk = JSON.parse(atob(publicKeyBase64));

  return crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    false,
    []
  );
}

async function deriveAesKey(myPrivateKeyBase64, theirPublicKeyBase64, saltBytes) {
  const privateKey = await importPrivateKey(myPrivateKeyBase64);
  const publicKey = await importPublicKey(theirPublicKeyBase64);

  const sharedBits = await crypto.subtle.deriveBits(
    {
      name: "ECDH",
      public: publicKey,
    },
    privateKey,
    256
  );

  const hkdfMaterial = await crypto.subtle.importKey(
    "raw",
    sharedBits,
    "HKDF",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: saltBytes,
      info: TEXT.encode("secure-message-site:v2:aes-gcm"),
    },
    hkdfMaterial,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptMessage({ message, myPrivateKey, theirPublicKey }) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const aesKey = await deriveAesKey(myPrivateKey, theirPublicKey, salt);

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    aesKey,
    TEXT.encode(message)
  );

  return {
    algorithm: "ECDH-P256 + HKDF-SHA256 + AES-256-GCM",
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(ciphertext),
  };
}

async function decryptMessage({ encrypted, myPrivateKey, theirPublicKey }) {
  const salt = base64ToBytes(encrypted.salt);
  const iv = base64ToBytes(encrypted.iv);
  const ciphertext = base64ToBytes(encrypted.ciphertext);

  const aesKey = await deriveAesKey(myPrivateKey, theirPublicKey, salt);

  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv,
    },
    aesKey,
    ciphertext
  );

  return FROM_TEXT.decode(plaintext);
}

function Button({ children, className = "", ...props }) {
  return (
    <button className={`btn ${className}`} {...props}>
      {children}
    </button>
  );
}

export default function App() {
  const [session, setSession] = useState(null);
  const [user, setUser] = useState(null);

  const [mode, setMode] = useState("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [username, setUsername] = useState("");
  const [profile, setProfile] = useState(null);
  const [privateKey, setPrivateKey] = useState(
    localStorage.getItem(PRIVATE_KEY_STORAGE) || ""
  );

  const [contacts, setContacts] = useState([]);
  const [contactSearch, setContactSearch] = useState("");
  const [foundUser, setFoundUser] = useState(null);

  const [selectedContactId, setSelectedContactId] = useState("");
  const [messages, setMessages] = useState([]);
  const [draft, setDraft] = useState("");
  const [openedMessages, setOpenedMessages] = useState({});

  const [status, setStatus] = useState("");

  const selectedContact = useMemo(() => {
    return contacts.find((contact) => contact.id === selectedContactId);
  }, [contacts, selectedContactId]);

  const chatMessages = useMemo(() => {
    if (!selectedContact || !user) return [];

    return messages.filter((message) => {
      const outgoing =
        message.sender_id === user.id &&
        message.receiver_id === selectedContact.contact_user_id;

      const incoming =
        message.receiver_id === user.id &&
        message.sender_id === selectedContact.contact_user_id;

      return outgoing || incoming;
    });
  }, [messages, selectedContact, user]);

  useEffect(() => {
    async function init() {
      const { data } = await supabase.auth.getSession();

      setSession(data.session);
      setUser(data.session?.user || null);
    }

    init();

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      setSession(nextSession);
      setUser(nextSession?.user || null);
    });

    return () => subscription.unsubscribe();
  }, []);

  useEffect(() => {
    if (!user) return;

    loadEverything();

    const channel = supabase
      .channel("messages-listener")
      .on(
        "postgres_changes",
        {
          event: "INSERT",
          schema: "public",
          table: "messages",
        },
        (payload) => {
          const message = payload.new;

          if (message.sender_id === user.id || message.receiver_id === user.id) {
            setMessages((prev) => {
              if (prev.some((item) => item.id === message.id)) return prev;
              return [...prev, message];
            });
          }
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [user]);

  async function loadEverything() {
    await loadProfile();
    await loadContacts();
    await loadMessages();
  }

  async function loadProfile() {
    const { data, error } = await supabase
      .from("profiles")
      .select("*")
      .eq("id", user.id)
      .maybeSingle();

    if (error) {
      setStatus(error.message);
      return;
    }

    setProfile(data);
  }

  async function loadContacts() {
    const { data, error } = await supabase
      .from("contacts")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) {
      setStatus(error.message);
      return;
    }

    setContacts(data || []);

    if (data?.[0]) {
      setSelectedContactId(data[0].id);
    }
  }

  async function loadMessages() {
    const { data, error } = await supabase
      .from("messages")
      .select("*")
      .order("created_at", { ascending: true });

    if (error) {
      setStatus(error.message);
      return;
    }

    setMessages(data || []);
  }

  async function register() {
    setStatus("Регистрирую...");

    const { data, error } = await supabase.auth.signUp({
      email,
      password,
    });

    if (error) {
      setStatus(error.message);
      return;
    }

    setStatus(
      "Аккаунт создан. Если Supabase просит подтверждение email — подтверди почту, потом войди."
    );

    if (data.session) {
      setSession(data.session);
      setUser(data.user);
    }
  }

  async function login() {
    setStatus("Вхожу...");

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      setStatus(error.message);
      return;
    }

    setSession(data.session);
    setUser(data.user);
    setStatus("Вход выполнен.");
  }

  async function logout() {
    await supabase.auth.signOut();

    setSession(null);
    setUser(null);
    setProfile(null);
    setContacts([]);
    setMessages([]);
    setSelectedContactId("");
    setStatus("Вы вышли.");
  }

  async function createProfileAndKeys() {
    if (!username.trim()) {
      setStatus("Введи username.");
      return;
    }

    setStatus("Создаю ключи...");

    const identity = await generateIdentity();

    localStorage.setItem(PRIVATE_KEY_STORAGE, identity.privateKey);
    setPrivateKey(identity.privateKey);

    const { data, error } = await supabase
      .from("profiles")
      .insert({
        id: user.id,
        username: username.trim().toLowerCase(),
        public_key: identity.publicKey,
      })
      .select()
      .single();

    if (error) {
      setStatus(error.message);
      return;
    }

    setProfile(data);
    setStatus("Профиль и ключи созданы.");
  }

  async function searchUser() {
    setFoundUser(null);

    if (!contactSearch.trim()) {
      setStatus("Введи username.");
      return;
    }

    const { data, error } = await supabase
      .from("profiles")
      .select("*")
      .eq("username", contactSearch.trim().toLowerCase())
      .maybeSingle();

    if (error) {
      setStatus(error.message);
      return;
    }

    if (!data) {
      setStatus("Пользователь не найден.");
      return;
    }

    if (data.id === user.id) {
      setStatus("Нельзя добавить самого себя.");
      return;
    }

    setFoundUser(data);
    setStatus("Пользователь найден.");
  }

  async function addContact() {
    if (!foundUser) return;

    const { error } = await supabase.from("contacts").insert({
      owner_id: user.id,
      contact_user_id: foundUser.id,
      contact_name: foundUser.username,
      contact_public_key: foundUser.public_key,
    });

    if (error) {
      setStatus(error.message);
      return;
    }

    setFoundUser(null);
    setContactSearch("");
    await loadContacts();
    setStatus("Контакт добавлен.");
  }

  async function sendMessage() {
    if (!draft.trim()) {
      setStatus("Введите сообщение.");
      return;
    }

    if (!selectedContact) {
      setStatus("Выбери контакт.");
      return;
    }

    if (!privateKey) {
      setStatus("Нет приватного ключа в этом браузере.");
      return;
    }

    setStatus("Шифрую и отправляю...");

    try {
      const encrypted = await encryptMessage({
        message: draft.trim(),
        myPrivateKey: privateKey,
        theirPublicKey: selectedContact.contact_public_key,
      });

      const { error } = await supabase.from("messages").insert({
        sender_id: user.id,
        receiver_id: selectedContact.contact_user_id,
        algorithm: encrypted.algorithm,
        salt: encrypted.salt,
        iv: encrypted.iv,
        ciphertext: encrypted.ciphertext,
      });

      if (error) {
        setStatus(error.message);
        return;
      }

      setDraft("");
      setStatus("Сообщение отправлено.");
    } catch (error) {
      setStatus(error.message);
    }
  }

  async function openMessage(message) {
    if (!selectedContact || !privateKey) return;

    try {
      const plain = await decryptMessage({
        encrypted: {
          salt: message.salt,
          iv: message.iv,
          ciphertext: message.ciphertext,
        },
        myPrivateKey: privateKey,
        theirPublicKey: selectedContact.contact_public_key,
      });

      setOpenedMessages((prev) => ({
        ...prev,
        [message.id]: plain,
      }));
    } catch {
      setOpenedMessages((prev) => ({
        ...prev,
        [message.id]:
          "Не удалось расшифровать. Возможно, это сообщение отправлено не этой парой ключей.",
      }));
    }
  }

  if (!session) {
    return (
      <div className="app">
        <div className="auth-card">
          <div className="badge">
            <ShieldCheck size={16} />
            Secure Message
          </div>

          <h1>{mode === "login" ? "Вход" : "Регистрация"}</h1>

          <input
            placeholder="Email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />

          <input
            placeholder="Пароль"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />

          {mode === "login" ? (
            <Button onClick={login}>Войти</Button>
          ) : (
            <Button onClick={register}>Создать аккаунт</Button>
          )}

          <button
            className="link-button"
            onClick={() => setMode(mode === "login" ? "register" : "login")}
          >
            {mode === "login"
              ? "Нет аккаунта? Зарегистрироваться"
              : "Уже есть аккаунт? Войти"}
          </button>

          {status && <p className="status">{status}</p>}
        </div>
      </div>
    );
  }

  if (!profile) {
    return (
      <div className="app">
        <div className="auth-card">
          <div className="badge">
            <KeyRound size={16} />
            Первый запуск
          </div>

          <h1>Создай username и ключи</h1>

          <p className="muted">
            Username нужен, чтобы другие могли найти тебя. Приватный ключ
            останется только в этом браузере.
          </p>

          <input
            placeholder="username"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
          />

          <Button onClick={createProfileAndKeys}>Создать профиль</Button>

          <Button className="secondary" onClick={logout}>
            Выйти
          </Button>

          {status && <p className="status">{status}</p>}
        </div>
      </div>
    );
  }

  return (
    <div className="app">
      <div className="container">
        <header className="header">
          <div>
            <div className="badge">
              <ShieldCheck size={16} />
              E2EE через Supabase
            </div>

            <h1>Secure Message</h1>

            <p>
              Ты вошёл как <b>@{profile.username}</b>. Сервер хранит только
              зашифрованные сообщения.
            </p>

            <p className="small-key">
              Мой публичный ключ: {shortKey(profile.public_key)}
            </p>
          </div>

          <Button className="danger" onClick={logout}>
            <LogOut size={16} />
            Выйти
          </Button>
        </header>

        <div className="layout">
          <aside className="sidebar">
            <div className="card">
              <h2>Добавить контакт</h2>

              <div className="search-row">
                <input
                  placeholder="username"
                  value={contactSearch}
                  onChange={(event) => setContactSearch(event.target.value)}
                />

                <Button onClick={searchUser}>
                  <Search size={16} />
                </Button>
              </div>

              {foundUser && (
                <div className="found-user">
                  <b>@{foundUser.username}</b>
                  <code>{shortKey(foundUser.public_key)}</code>

                  <Button onClick={addContact}>
                    <UserPlus size={16} />
                    Добавить
                  </Button>
                </div>
              )}
            </div>

            <div className="card">
              <h2>Контакты</h2>

              {contacts.length === 0 ? (
                <p className="muted">Контактов пока нет.</p>
              ) : (
                <div className="contacts">
                  {contacts.map((contact) => (
                    <button
                      key={contact.id}
                      className={
                        selectedContactId === contact.id
                          ? "contact active"
                          : "contact"
                      }
                      onClick={() => {
                        setSelectedContactId(contact.id);
                        setOpenedMessages({});
                      }}
                    >
                      <b>@{contact.contact_name}</b>
                      <code>{shortKey(contact.contact_public_key)}</code>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </aside>

          <main className="chat-card">
            <div className="chat-top">
              <div>
                <h2>
                  {selectedContact
                    ? `@${selectedContact.contact_name}`
                    : "Выбери контакт"}
                </h2>

                <p>
                  {selectedContact
                    ? "Сообщения шифруются перед отправкой в Supabase"
                    : "Добавь или выбери контакт слева"}
                </p>
              </div>

              <div className="encrypt-label">
                <Lock size={16} />
                AES-256-GCM
              </div>
            </div>

            <div className="messages">
              {!selectedContact ? (
                <div className="empty">Выбери контакт.</div>
              ) : chatMessages.length === 0 ? (
                <div className="empty">Сообщений пока нет.</div>
              ) : (
                chatMessages.map((message) => {
                  const isMine = message.sender_id === user.id;

                  return (
                    <div
                      key={message.id}
                      className={isMine ? "message mine" : "message"}
                    >
                      <div className="message-head">
                        <div>
                          <b>{isMine ? "Ты" : selectedContact.contact_name}</b>
                          <span>
                            {new Date(message.created_at).toLocaleString()}
                          </span>
                        </div>

                        <Button
                          className="secondary small"
                          onClick={() => openMessage(message)}
                        >
                          Расшифровать
                        </Button>
                      </div>

                      <div className="cipher">
                        <div>alg: {message.algorithm}</div>
                        <div>iv: {message.iv}</div>
                        <div>salt: {message.salt}</div>
                        <div>ciphertext: {message.ciphertext}</div>
                      </div>

                      {openedMessages[message.id] && (
                        <div className="plain">{openedMessages[message.id]}</div>
                      )}
                    </div>
                  );
                })
              )}
            </div>

            <div className="composer">
              <textarea
                placeholder="Введите сообщение..."
                value={draft}
                onChange={(event) => setDraft(event.target.value)}
              />

              <Button onClick={sendMessage} disabled={!selectedContact}>
                <Send size={18} />
                Отправить
              </Button>
            </div>
          </main>
        </div>

        {status && <p className="status bottom-status">{status}</p>}
      </div>
    </div>
  );
}
