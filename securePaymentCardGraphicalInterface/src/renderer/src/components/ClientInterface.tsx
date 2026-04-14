import {
  AUTH_PIN,
  CLOSE_CLIENT_INTERFACE,
  GUI_SEPARATOR_CHAR,
  INSTALL_PIN,
  PIN_SEPARATOR_CHAR,
  setState,
  UNINSTALL
} from '@renderer/App'

interface ClientInterfacePropos {
  startSessionMode: boolean
  balance: number
  pinStr: string[]
  webSocket: WebSocket
  showPinInput: boolean
  sessionStarted: boolean
  setLogs: setState<string[]>
  securePaymentCardID: string
  setStartSessionMode: setState<boolean>
  setPinStr: setState<string[]>
  setShowPinInput: setState<boolean>
  setSessionStarted: setState<boolean>
  setAuthenticated: setState<boolean>
}

interface UserPin {
  pin: string
}

function handlePinSubmit(
  pinStr: string[],
  setLogs: setState<string[]>,
): UserPin {
  if (!pinStr.every((element: string) => element.trim().length > 0 && !isNaN(parseInt(element)))) {
    setLogs((prevState) => [...prevState, 'Un code PIN doit contenir 6 chiffres'])
    return { pin: ''}
  }
  let pinPayload: string = ''
  for (let i = 0; i < pinStr.length; i++) {
    if (i === 0) {
      pinPayload += pinStr[i]
    } else {
      pinPayload += `${PIN_SEPARATOR_CHAR}${pinStr[i]}`
    }
  }

  return { pin: pinPayload }
}
function deploy(
  webSocket: WebSocket,
  pinStr: string[],
  setLogs: setState<string[]>,
  setShowPinInput: setState<boolean>,
  setSessionStarted: setState<boolean>,
): void {
  setShowPinInput(false)

  const userPin: UserPin = handlePinSubmit(pinStr, setLogs)
  if (userPin.pin.length > 0) {
    webSocket.send(`${INSTALL_PIN}${GUI_SEPARATOR_CHAR}${JSON.stringify(userPin)}`)
    //webSocket.send(`${DEPLOY}${GUI_SEPARATOR_CHAR}`)
    setSessionStarted(false)
  }
}

function startSession(
  webSocket: WebSocket,
  pinStr: string[],
  setLogs: setState<string[]>,
  setShowPinInput: setState<boolean>,
): void {
  setShowPinInput(false)

  const userPin: UserPin = handlePinSubmit(pinStr, setLogs)
  if (userPin.pin.length > 0) {
    webSocket.send(`${AUTH_PIN}${GUI_SEPARATOR_CHAR}${JSON.stringify(userPin)}`)
    //webSocket.send(`${START_OR_RESUME_SESSION}${GUI_SEPARATOR_CHAR}`)
  }
}

function uninstall(webSocket: WebSocket, setSessionStarted: setState<boolean>): void {
  webSocket.send(`${UNINSTALL}${GUI_SEPARATOR_CHAR}`)
  setSessionStarted(false)
}

function closeClientInterface(
  webSocket: WebSocket,
  setSessionStarted: setState<boolean>,
  setAuthenticated: setState<boolean>
): void {
  webSocket.send(`${CLOSE_CLIENT_INTERFACE}${GUI_SEPARATOR_CHAR}`)
  setAuthenticated(false)
  setSessionStarted(false)
}

function ClientInterface({
  startSessionMode,
  balance,
  pinStr,
  webSocket,
  showPinInput,
  sessionStarted,
  setLogs,
  securePaymentCardID,
  setStartSessionMode,
  setPinStr,
  setShowPinInput,
  setSessionStarted,
  setAuthenticated,
}: ClientInterfacePropos): React.JSX.Element {
  return (
    <>
      <div className="container col-xxl-8 px-4 py-5">
        <div className="row flex-lg-row-reverse align-items-center g-5 py-5">
          <h1 className="display-5 fw-bold text-body-emphasis lh-1 mb-3">Menu</h1>

          <div className="col-10 col-sm-8 col-lg-6">
            <div
              className="card text-bg-light d-block mx-lg-auto img-fluid showing shadow-sm"
              style={{ width: 800, height: 250, background: '#afc5df !important' }}
            >
              <div className="card-img-overlay">
                <h5 className="card-title">
                  {securePaymentCardID.length > 0
                    ? securePaymentCardID
                    : 'CARD-00000000-000000-00000'}
                </h5>
                <p className="card-text">
                  {balance >= 0 ? `Solde : ${balance}` : `Solde : -`}
                  <br />
                  <small>Secure Payment Card</small>
                </p>
                <div className="row">
                  <i className="bi bi-lock fs-2 mb-3"></i>
                </div>
              </div>
            </div>
          </div>

          <div className="col-lg-6">
            <div className="d-grid gap-2">
              <button
                type="button"
                className="btn btn-outline-success btn-lg px-4"
                onClick={() => {
                  setStartSessionMode(false)
                  setPinStr(['', '', '', '', '', ''])
                  setShowPinInput(true)
                }}
              >
                Déployer une nouvelle carte
              </button>
              <button
                type="button"
                className={`btn btn${!sessionStarted ? '-outline' : ''}-warning btn-lg px-4`}
                onClick={() => {
                  setStartSessionMode(true)
                  if (!sessionStarted) {
                    setPinStr(['', '', '', '', '', ''])
                    setShowPinInput(true)
                  }
                }}
              >
                Démarrage / reprise d'une session
              </button>
              <button
                type="button"
                className="btn btn-outline-danger btn-lg px-4"
                onClick={() => {
                  setStartSessionMode(false)
                  uninstall(webSocket, setSessionStarted)
                }}
              >
                Désinstaller
              </button>
              <button
                type="button"
                className="btn btn-outline-dark btn-lg px-4"
                onClick={() => {
                  closeClientInterface(webSocket, setSessionStarted, setAuthenticated)
                }}
              >
                Fin
              </button>
            </div>
          </div>
        </div>
      </div>

      {showPinInput ? (
        <div className="container my-5">
          <div className="row p-4 pb-0 pe-lg-0 pt-lg-5 align-items-center rounded-3 border shadow-lg">
            <div className="p-3 p-lg-5 pt-lg-3">
              <h1 className="display-4 fw-bold lh-1 text-body-emphasis">PIN</h1>
              <div className="d-grid gap-2 d-md-flex justify-content-md-start mb-4 mb-lg-3"></div>
              <div className="input-group">
                {pinStr.map((value: string, index: number) => (
                  <input
                    type="text"
                    className="form-control text-center"
                    key={index}
                    defaultValue={value}
                    onChange={(evt) => {
                      setPinStr((prevState) => {
                        const newArray = [...prevState]
                        const inputAsInt: number = parseInt(evt.target.value)
                        if (!isNaN(inputAsInt)) {
                          newArray[index] = inputAsInt.toString()
                        }
                        return newArray
                      })
                    }}
                  />
                ))}
              </div>
              <div className="d-grid gap-2, mt-2">
                <button
                  className="btn btn-primary"
                  type="button"
                  onClick={() => {
                    if (startSessionMode) {
                      startSession(webSocket, pinStr, setLogs, setShowPinInput)
                    } else {
                      deploy(webSocket, pinStr, setLogs, setShowPinInput, setSessionStarted)
                    }
                  }}
                >
                  Envoyer
                </button>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <></>
      )}
    </>
  )
}

export default ClientInterface
