function LandingPage(): React.JSX.Element {
  return (
    <div className="px-4 pt-5 my-5 text-center border-bottom">
      <h1 className="display-4 fw-bold text-body-emphasis">Test</h1>
      <div className="col-lg-6 mx-auto">
        <p className="lead mb-4">...</p>
        <div className="d-grid gap-2 d-sm-flex justify-content-sm-center mb-5">
          <button type="button" className="btn btn-primary btn-lg px-4 me-sm-3">
            Test
          </button>
          <button type="button" className="btn btn-outline-secondary btn-lg px-4">
            Test
          </button>
        </div>
      </div>

      <div className="overflow-hidden" style={{ maxHeight: '30vh' }}>
        <div className="container px-5">
          <div
            className="card text-bg-light d-block mx-lg-auto img-fluid shadow-lg m-0 border-0"
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
      </div>
    </div>
  )
}

export default LandingPage
