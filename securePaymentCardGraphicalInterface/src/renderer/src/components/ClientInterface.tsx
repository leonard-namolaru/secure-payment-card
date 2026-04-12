import {
  CLOSE_CLIENT_INTERFACE,
  DEPLOY,
  SEPARATOR_CHAR,
  setState,
  START_OR_RESUME_SESSION,
  UNINSTALL
} from '@renderer/App'

interface ClientInterfacePropos {
  webSocket: WebSocket
  sessionStarted: boolean
}

function deploy(webSocket: WebSocket): void {
  webSocket.send(`${DEPLOY}${SEPARATOR_CHAR}`);
}

function startOrResumeSession(webSocket: WebSocket): void {
  webSocket.send(`${START_OR_RESUME_SESSION}${SEPARATOR_CHAR}`);
}

function uninstall(webSocket: WebSocket): void {
  webSocket.send(`${UNINSTALL}${SEPARATOR_CHAR}`);
}

function closeClientInterface(webSocket: WebSocket): void {
  webSocket.send(`${CLOSE_CLIENT_INTERFACE}${SEPARATOR_CHAR}`);
}

function ClientInterface({
  webSocket,
  sessionStarted,
}: ClientInterfacePropos): React.JSX.Element {
  return (
    <div className="container col-xxl-8 px-4 py-5">
      <div className="row flex-lg-row-reverse align-items-center g-5 py-5">
        <h1 className="display-5 fw-bold text-body-emphasis lh-1 mb-3">Menu</h1>

        <div className="col-10 col-sm-8 col-lg-6">
          <div
            className="card text-bg-light d-block mx-lg-auto img-fluid"
            style={{ width: 800, height: 250 }}
          >
            <div className="card-img-overlay">
              <h5 className="card-title">CARD-20260412-181049-00338</h5>
              <p className="card-text">Solde : 100</p>
              <p className="card-text">
                <small>...</small>
              </p>
            </div>
          </div>
        </div>

        <div className="col-lg-6">
          <div className="d-grid gap-2">
            <button
              type="button"
              className="btn btn-outline-success btn-lg px-4"
              onClick={() => {
                deploy(webSocket)
              }}
            >
              Déployer
            </button>
            <button
              type="button"
              className={`btn btn${!sessionStarted ? '-outline' : ''}-warning btn-lg px-4`}
              onClick={() => {
                startOrResumeSession(webSocket)
              }}
            >
              Démarrage / reprise d'une session
            </button>
            <button
              type="button"
              className="btn btn-outline-danger btn-lg px-4"
              onClick={() => {
                uninstall(webSocket)
              }}
            >
              Désinstaller
            </button>
            <button
              type="button"
              className="btn btn-outline-dark btn-lg px-4"
              onClick={() => {
                closeClientInterface(webSocket)
              }}
            >
              Fin
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

export default ClientInterface
