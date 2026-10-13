import React from "react";
import "../../styles/compliance.css";


function ComplianceCard({ compliance }) {


  if (!compliance) {


    return (

      <div className="compliance-card">

        <h3>
          CIS Compliance
        </h3>

        <p>
          No compliance data available
        </p>

      </div>

    );

  }






  return (


    <div className="compliance-card">





      <div className="compliance-header">



        <h3>

          {compliance.framework}

        </h3>





        <span className="score-badge">


          {compliance.compliance_score}%

        
        </span>



      </div>








      <div className="compliance-stats">





        <div>


          <strong>

            {compliance.controls?.total || 0}

          </strong>


          <p>
            Total Controls
          </p>


        </div>








        <div>


          <strong className="failed">


            {compliance.controls?.failed || 0}


          </strong>



          <p>
            Failed
          </p>


        </div>








        <div>


          <strong className="passed">


            {compliance.controls?.passed || 0}


          </strong>



          <p>
            Passed
          </p>


        </div>





      </div>





    </div>


  );


}



export default ComplianceCard;