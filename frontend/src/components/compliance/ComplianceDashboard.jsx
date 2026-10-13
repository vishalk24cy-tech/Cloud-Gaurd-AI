import React, { useEffect, useState } from "react";

import api from "../../services/api";

import ComplianceCard from "./ComplianceCard";
import FailedControls from "./FailedControls";

import "../../styles/compliance.css";


function ComplianceDashboard() {


    const [compliance, setCompliance] = useState(null);

    const [loading, setLoading] = useState(true);





    const loadCompliance = async () => {


        try {


            const response = await api.get(
                "/compliance/"
            );


            setCompliance(
                response.data
            );


        }

        catch(error) {


            console.error(
                "Compliance Error:",
                error
            );


        }

        finally {


            setLoading(false);


        }


    };







    useEffect(() => {


        loadCompliance();


    }, []);







    if(loading) {


        return (

            <div className="compliance-loading">

                Loading Compliance Data...

            </div>

        );

    }







    if(!compliance) {


        return (

            <div className="compliance-loading">

                No Compliance Data Found

            </div>

        );

    }








    return (

        <div className="compliance-dashboard">





            <h2>

                CloudGuardAI Compliance Center

            </h2>





            <p className="subtitle">

                CIS AWS Foundations Benchmark Security Assessment

            </p>








            <ComplianceCard

                compliance={
                    compliance.compliance
                }

            />









            <FailedControls


                controls={

                    compliance
                    .compliance
                    .failed_controls || []

                }


            />





        </div>

    );


}



export default ComplianceDashboard;