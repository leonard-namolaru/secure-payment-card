import { AUTHENTICATION_REQUEST, GUI_SEPARATOR_CHAR, setState } from '@renderer/App'

interface AuthenticationPropos {
  email: string
  password: string
  webSocket: WebSocket,
  setLogs: setState<string[]>,
  setEmail: setState<string>,
  setPassword: setState<string>,
}


function handleAuthentication(webSocket: WebSocket, email: string, password: string, setLogs: setState<string[]>): void {
  if (email.trim().length === 0 || password.trim().length === 0) {
    setLogs((prevState) => [
      ...prevState,
      "Il est obligatoire de saisir une adresse mail et un mot de passe pour s'authentifier auprès du serveur."
    ]);
    return;
  }

  const object = {email: email, password: password};
  webSocket.send(`${AUTHENTICATION_REQUEST}${GUI_SEPARATOR_CHAR}${JSON.stringify(object)}`);
}

function Authentication({
  email,
  password,
  webSocket,
  setLogs,
  setEmail,
  setPassword
}: AuthenticationPropos): React.JSX.Element {
  return (
    <div className="container col-xl-10 col-xxl-8 px-4 py-5">
      <div className="row align-items-center g-lg-5 py-5">
        <div className="col-lg-7 text-center text-lg-start">
          <h1 className="display-4 fw-bold lh-1 text-body-emphasis mb-3">
            Interface de gestion des cartes de paiement
          </h1>
          <p className="col-lg-10 fs-4">...</p>
        </div>
        <div className="col-md-10 mx-auto col-lg-5">
          <div className="p-4 p-md-5 border rounded-3 bg-body-tertiary">
            <div className="form-floating mb-3">
              <input
                type="email"
                className="form-control"
                id="floatingInput"
                defaultValue={email}
                onChange={(evt) => {
                  setEmail(evt.target.value)
                }}
              />
              <label htmlFor="floatingInput">Adresse mail</label>
            </div>
            <div className="form-floating mb-3">
              <input
                type="password"
                className="form-control"
                id="floatingPassword"
                defaultValue={password}
                onChange={(evt) => {
                  setPassword(evt.target.value)
                }}
              />
              <label htmlFor="floatingPassword">Mot de passe</label>
            </div>
            <button
              className="w-100 btn btn-lg btn-primary"
              onClick={() => {
                handleAuthentication(webSocket, email, password, setLogs)
              }}
            >
              <i className="bi bi-box-arrow-right"></i>
              &nbsp;Se connecter
            </button>
            <hr className="my-4" />
            <small className="text-body-secondary">...</small>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Authentication
