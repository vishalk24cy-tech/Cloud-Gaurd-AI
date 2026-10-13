import React from "react";
import "../../styles/compliance.css";


function FailedControls({ controls }) {


  if (!controls || controls.length === 0) {


    return (

      <div className="failed-controls-card">


        <h3>
          Failed CIS Controls
        </h3>


        <p>
          No failed controls detected 🎉
        </p>


      </div>

    );

  }







  return (


    <div className="failed-controls-card">



      <h3>
        Failed CIS Controls
      </h3>






      {
        controls.map((control,index)=>(


          <div

            key={index}

            className="control-item"

          >






            <div className="control-title">





              <span

                className={
                  control.severity === "HIGH"
                  ?
                  "severity-high"
                  :
                  "severity-medium"
                }

              >

                {control.severity}

              </span>







              <strong>

                {control.control}

              </strong>






            </div>









            <p>

              Status:

              {" "}

              {control.status}

            </p>








            <small>

              Recommendation:

              {" "}

              {control.recommendation}

            </small>







          </div>


        ))

      }






    </div>


  );


}


export default FailedControls;