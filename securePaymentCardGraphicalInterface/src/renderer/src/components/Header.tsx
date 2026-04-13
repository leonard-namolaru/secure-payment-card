import logo from '../assets/credit-card-2-back-fill.svg'

interface HeaderPropos {
  logs: string[]
  connected: boolean
  closeWebSocketFunction: () => void
  connectWebSocketFunction: () => void
}

function Header({ logs, connected, closeWebSocketFunction, connectWebSocketFunction }: HeaderPropos): React.JSX.Element {
  return (
    <div className="px-4 py-5 my-5 text-center">
      <img
        className="d-block mx-auto mb-4"
        src={logo}
        alt="Secure Payment Card"
        width="92"
        height="77"
      />
      <h1 className="display-5 fw-bold text-body-emphasis">Secure Payment Card</h1>
      <div className="col-lg-6 mx-auto">
        <div className="lead mb-4">
          {logs.map((log: string, index: number) =>
            logs.length - index <= 5 ? (
              <p key={index}>
                <i className="bi bi-info-square"></i>
                &nbsp;{log}
              </p>
            ) : (
              <span key={index}></span>
            )
          )}
        </div>
        <div className="d-grid gap-2 d-sm-flex justify-content-sm-center">
          {!connected ? (
            <button
              type="button"
              className="btn btn-primary btn-lg px-4 gap-3"
              onClick={() => {
                connectWebSocketFunction()
              }}
            >
              <i className="bi bi-chevron-compact-right"></i>
              &nbsp;Connexion
            </button>
          ) : (
            <></>
          )}

          {connected ? (
            <button
              type="button"
              className="btn btn-outline-secondary btn-lg px-4"
              onClick={() => {
                closeWebSocketFunction()
              }}
            >
              <i className="bi bi-box-arrow-left"></i>
              &nbsp;Déconnexion
            </button>
          ) : (
            <></>
          )}
        </div>
      </div>
    </div>
  )
}

export default Header
