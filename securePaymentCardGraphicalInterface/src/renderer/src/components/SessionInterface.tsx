
function SessionInterface(): React.JSX.Element {

  return (
    <div className="container my-5">
      <div className="row p-4 pb-0 pe-lg-0 pt-lg-5 align-items-center rounded-3 border shadow-lg">
        <div className="col-lg-7 p-3 p-lg-5 pt-lg-3">
          <h1 className="display-4 fw-bold lh-1 text-body-emphasis">Gestion du solde</h1>
          <p className="lead">...</p>
          <div className="d-grid gap-2 d-md-flex justify-content-md-start mb-4 mb-lg-3">
            <button type="button" className="btn btn-outline-success btn-lg px-4 me-md-2 fw-bold">
              Crédit
            </button>
            <button type="button" className="btn btn-outline-danger btn-lg px-4">
              Débit
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

export default SessionInterface
