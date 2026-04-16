import {
  CREDIT, DEBIT,
  CREDIT_TRANSACTION_MODE,
  DEBIT_TRANSACTION_MODE,
  GUI_SEPARATOR_CHAR,
  setState
} from '@renderer/App'

interface SessionInterfacePropos {
  webSocket: WebSocket
  transactionMode: string
  setLogs: setState<string[]>
  transactionAmountAsStr: string
  setTransactionMode: setState<string>
  setTransactionAmountAsStr: setState<string>
}

interface Transaction {
  amount: number
}

function handleTransaction(
  webSocket: WebSocket,
  transactionAsString: string,
  transactionMode: string,
  setLogs: setState<string[]>
): void {
    if (transactionMode !== CREDIT_TRANSACTION_MODE && transactionMode !== DEBIT_TRANSACTION_MODE) {
      setLogs((prevState) => [
        ...prevState,
        'Il est obligatoire de sélectionner un mode de transaction (crédit / débit).'
      ])
      return;
    }

    if (transactionAsString.trim().length > 0) {
      const transactionAsInt: number = parseInt(transactionAsString)
      if (!isNaN(transactionAsInt) && transactionAsInt > 0) {
        const transaction: Transaction = { amount: parseInt(transactionAsString) }
        let transactionModeCode: number = -1
        if (transactionMode === CREDIT_TRANSACTION_MODE) {
          transactionModeCode = CREDIT
        } else if (transactionMode === DEBIT_TRANSACTION_MODE) {
          transactionModeCode = DEBIT
        }
        webSocket.send(`${transactionModeCode}${GUI_SEPARATOR_CHAR}${JSON.stringify(transaction)}`)
        return
      }
    }

  setLogs((prevState) => [
    ...prevState,
    'Il est obligatoire de saisir un montant de transaction supérieur à zéro.'
  ])
}

function SessionInterface({
  webSocket,
  setLogs,
  transactionMode,
  transactionAmountAsStr,
  setTransactionMode,
  setTransactionAmountAsStr
}: SessionInterfacePropos): React.JSX.Element {
  return (
    <div className="container my-5">
      <div className="row p-4 pb-0 pe-lg-0 pt-lg-5 align-items-center rounded-3 border shadow-lg">
        <div className="col-lg-7 p-3 p-lg-5 pt-lg-3">
          <h1 className="display-4 fw-bold lh-1 text-body-emphasis">Gestion du solde</h1>
          <p className="lead">Opérations disponibles :</p>
          <div className="d-grid gap-2 d-md-flex justify-content-md-start mb-4 mb-lg-3">
            <button
              type="button"
              className={`btn btn${transactionMode !== CREDIT_TRANSACTION_MODE ? '-outline' : ''}-success btn-lg px-4 me-md-2 fw-bold`}
              onClick={() => {
                setTransactionMode(CREDIT_TRANSACTION_MODE)
              }}
            >
              Crédit
            </button>
            <button
              type="button"
              className={`btn btn${transactionMode !== DEBIT_TRANSACTION_MODE ? '-outline' : ''}-danger btn-lg px-4`}
              onClick={() => {
                setTransactionMode(DEBIT_TRANSACTION_MODE)
              }}
            >
              Débit
            </button>
          </div>
        </div>
        <div className="col-lg-3 p-3 p-lg-5 pt-lg-3">
          <form className="row g-3">
            <div className="col-auto">Montant</div>
            <div className="col-auto">
              <label htmlFor="inputAmount" className="visually-hidden">
                Montant
              </label>
              <input
                type="number"
                className="form-control"
                id="inputAmount"
                placeholder="0"
                max="127"
                min="0"
                onChange={ (evt) => { setTransactionAmountAsStr(evt.target.value) }}
              />
            </div>
            <div className="col-auto">
              <button type="button" className="btn btn-primary mb-3"
                      onClick={() =>
                      { handleTransaction(
                        webSocket, transactionAmountAsStr, transactionMode, setLogs); }}>
                Effectuer l'opération
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}

export default SessionInterface
