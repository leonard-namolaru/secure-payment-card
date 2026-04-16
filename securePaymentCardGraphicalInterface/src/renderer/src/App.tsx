import { Dispatch, SetStateAction, useState } from 'react'

import Header from '@renderer/components/Header'
import Divider from '@renderer/components/Divider'
import Authentication from '@renderer/components/Authentication'
import ClientInterface from '@renderer/components/ClientInterface'
import SessionInterface from '@renderer/components/SessionInterface'

export const SECURE_PAYMENT_CARD_DEFAULT_ID = 'CARD-00000000-000000-00000';
export const PIN_SEPARATOR_CHAR: string = ",";
export const GUI_SEPARATOR_CHAR: string = "|";
export const CLIENT_SEPARATOR_CHAR: string = ':';

export const ID_PREFIX: string = 'ID';
export const BALANCE_PREFIX: string = 'Solde';

export const DEBIT_TRANSACTION_MODE: string = 'DEBIT';
export const CREDIT_TRANSACTION_MODE: string = 'CREDIT';

export const AUTHENTICATION_REQUEST: number = 0;
export const DEPLOY: number = 1;
export const START_OR_RESUME_SESSION: number = 2;
export const UNINSTALL: number = 3;
export const CLOSE_CLIENT_INTERFACE: number = 4;
export const DEBIT: number = 5;
export const CREDIT: number = 6;
export const INSTALL_PIN: number = 7
export const AUTH_PIN: number = 8

export type Nullable<T> = T | null;
export type setState<T> = Dispatch<SetStateAction<T>>;

interface SetAppElementsObject {
  setEmail: setState<string>
  setLogs: setState<string[]>
  setBalance: setState<number>
  setPinStr: setState<string[]>
  setPassword: setState<string>
  setConnected: setState<boolean>
  setShowPinInput: setState<boolean>
  setAuthenticated: setState<boolean>
  setSessionStarted: setState<boolean>
  setTransactionMode: setState<string>
  setStartSessionMode: setState<boolean>
  setSecurePaymentCardID: setState<string>
  setTransactionAmountAsStr: setState<string>
  setWebSocketObject: setState<Nullable<WebSocket>>
}

function reset(setAppElementsObject: SetAppElementsObject): void {
  setAppElementsObject.setLogs([]);
  setAppElementsObject.setBalance(-1);
  setAppElementsObject.setWebSocketObject(null)

  setAppElementsObject.setConnected(false)
  setAppElementsObject.setAuthenticated(false);
  setAppElementsObject.setSessionStarted(false);

  setAppElementsObject.setEmail('')
  setAppElementsObject.setPassword('')
  setAppElementsObject.setTransactionMode('')
  setAppElementsObject.setSecurePaymentCardID(SECURE_PAYMENT_CARD_DEFAULT_ID)
  setAppElementsObject.setTransactionAmountAsStr('')

  setAppElementsObject.setStartSessionMode(false);
  setAppElementsObject.setShowPinInput(false);
  setAppElementsObject.setPinStr(['', '', '', '', '', '']);
}


function initWebSocketListeners(
  webSocket: WebSocket,
  setAppElementsObject: SetAppElementsObject
): void {
  webSocket.addEventListener('open', () => {
    setAppElementsObject.setLogs((prevState) => [
      ...prevState,
      'La connexion avec le client a été établie avec succès.'
    ])
    setAppElementsObject.setConnected(true)
  })

  webSocket.addEventListener('close', () => {
    setAppElementsObject.setLogs((prevState) => [...prevState, 'Fin de la connexion.'])
    setAppElementsObject.setConnected(false)
    setAppElementsObject.setWebSocketObject(null)
  })

  webSocket.addEventListener('message', (e) => {
    const message: string = e.data.toString().trim().replaceAll("\n", "")
    if (message.length === 0) {
      return;
    }

    if (message.trim() === "L'authentification auprès du serveur a réussi.") {
        setAppElementsObject.setAuthenticated(true)
    }

    if (message.trim() === 'La session a démarré') {
      setAppElementsObject.setSessionStarted(true)
    }

    if (message.trim().startsWith(ID_PREFIX) && message.indexOf(CLIENT_SEPARATOR_CHAR) !== -1) {
      let securePaymentCardID: string = ''
      const tmp: string[] = message.split(CLIENT_SEPARATOR_CHAR).map((str) => str.trim())
      if (tmp.length > 1) {
        securePaymentCardID = tmp[1]
      }

      setAppElementsObject.setSecurePaymentCardID(securePaymentCardID)
      return
    }

    if (message.trim().startsWith(BALANCE_PREFIX) && message.indexOf(CLIENT_SEPARATOR_CHAR) !== -1) {
      let balance: number = -1
      const tmp: string[] = message.split(CLIENT_SEPARATOR_CHAR).map((str) => str.trim())
      if (tmp.length > 1) {
        balance = parseInt(tmp[1])
      }

      if (!isNaN(balance)) {
        setAppElementsObject.setBalance(balance)
      }
      return
    }

    setAppElementsObject.setLogs((prevState) => [...prevState, e.data])
  })

  webSocket.addEventListener('error', () => {
    setAppElementsObject.setLogs((prevState) => [
      ...prevState,
      "Une erreur inattendue s'est produite."
    ])
  })
}

function connectWebSocket(setAppElementsObject: SetAppElementsObject): WebSocket {
  reset(setAppElementsObject)

  const url = 'ws://127.0.0.1/'
  const webSocket: WebSocket = new WebSocket(url)
  initWebSocketListeners(webSocket, setAppElementsObject)
  setAppElementsObject.setWebSocketObject(webSocket)
  return webSocket
}

function closeWebSocket(
  webSocket: Nullable<WebSocket>,
  setAppElementsObject: SetAppElementsObject
): void {
  if (webSocket !== null) {
    webSocket.close()
  }

  setAppElementsObject.setConnected(false)
  setAppElementsObject.setAuthenticated(false)
  setAppElementsObject.setSessionStarted(false)
  setAppElementsObject.setWebSocketObject(null)
}

function App(): React.JSX.Element {
  const [email, setEmail] = useState<string>('')
  const [password, setPassword] = useState<string>('')

  const [balance, setBalance] = useState<number>(-1)
  const [securePaymentCardID, setSecurePaymentCardID] = useState<string>(
    SECURE_PAYMENT_CARD_DEFAULT_ID
  )

  const [startSessionMode, setStartSessionMode] = useState<boolean>(false)
  const [showPinInput, setShowPinInput] = useState<boolean>(false)
  const [pinStr, setPinStr] = useState<string[]>(['', '', '', '', '', ''])

  const [logs, setLogs] = useState<string[]>([])
  const [connected, setConnected] = useState<boolean>(false)
  const [authenticated, setAuthenticated] = useState<boolean>(false)
  const [sessionStarted, setSessionStarted] = useState<boolean>(false)
  const [webSocketObject, setWebSocketObject] = useState<Nullable<WebSocket>>(null)

  const [transactionMode, setTransactionMode] = useState<string>('')
  const [transactionAmountAsStr, setTransactionAmountAsStr] = useState<string>('')

  const setAppElementsObject: SetAppElementsObject = {
    setLogs: setLogs,
    setEmail: setEmail,
    setBalance: setBalance,
    setPassword: setPassword,
    setConnected: setConnected,
    setAuthenticated: setAuthenticated,
    setSessionStarted: setSessionStarted,
    setTransactionMode: setTransactionMode,
    setWebSocketObject: setWebSocketObject,
    setSecurePaymentCardID: setSecurePaymentCardID,
    setTransactionAmountAsStr: setTransactionAmountAsStr,
    setStartSessionMode: setStartSessionMode,
    setShowPinInput: setShowPinInput,
    setPinStr: setPinStr
  }

  return (
    <main>
      <Header
        connectWebSocketFunction={() => {
          connectWebSocket(setAppElementsObject)
        }}
        closeWebSocketFunction={() => {
          closeWebSocket(webSocketObject, setAppElementsObject)
        }}
        logs={logs}
        connected={connected}
      />

      <Divider />

      {webSocketObject !== null && connected && !authenticated ? (
        <Authentication
          email={email}
          password={password}
          webSocket={webSocketObject}
          setLogs={setLogs}
          setEmail={setEmail}
          setPassword={setPassword}
        />
      ) : (
        <></>
      )}

      {webSocketObject !== null && connected && authenticated ? (
        <ClientInterface
          setBalance={setBalance}
          setSecurePaymentCardID={setSecurePaymentCardID}
          startSessionMode={startSessionMode}
          pinStr={pinStr}
          balance={balance}
          setLogs={setLogs}
          setStartSessionMode={setStartSessionMode}
          setPinStr={setPinStr}
          showPinInput={showPinInput}
          webSocket={webSocketObject}
          sessionStarted={sessionStarted}
          setShowPinInput={setShowPinInput}
          setAuthenticated={setAuthenticated}
          setSessionStarted={setSessionStarted}
          securePaymentCardID={securePaymentCardID}
        />
      ) : (
        <></>
      )}

      {webSocketObject !== null && connected && authenticated && sessionStarted ? (
        <SessionInterface
          setLogs={setLogs}
          webSocket={webSocketObject}
          transactionMode={transactionMode}
          setTransactionMode={setTransactionMode}
          transactionAmountAsStr={transactionAmountAsStr}
          setTransactionAmountAsStr={setTransactionAmountAsStr}
        />
      ) : (
        <></>
      )}
    </main>
  )
}

export default App
