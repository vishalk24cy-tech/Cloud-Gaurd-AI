import { useEffect, useState } from "react";
import api from "../services/api";

import "./ComplianceDashboard.css";


function ComplianceDashboard(){


    const [data,setData] = useState(null);

    const [loading,setLoading] = useState(true);





    useEffect(()=>{

        loadCompliance();

    },[]);






    const loadCompliance = async()=>{


        try{


            const response = await api.get(
                "/compliance/"
            );


            setData(
                response.data
            );


        }

        catch(error){


            console.log(
                "Compliance Error:",
                error
            );


        }

        finally{


            setLoading(false);


        }


    };







    if(loading){


        return (

            <div className="compliance-card">

                Loading Compliance Data...

            </div>

        );


    }







    if(!data){


        return (

            <div className="compliance-card">

                No Compliance Data Available

            </div>

        );


    }






    const compliance = data.compliance;







    return (


        <div className="compliance-card">



            <div className="compliance-header">


                <div>

                    <h2>
                        Compliance Center
                    </h2>


                    <p>
                        CIS AWS Benchmark & NIST Security Assessment
                    </p>


                </div>


            </div>









            <div className="compliance-score">


                <div className="score-circle">


                    <h1>
                        {compliance.compliance_score}%
                    </h1>


                    <p>
                        Overall Compliance
                    </p>


                </div>



            </div>









            <div className="framework-grid">



                <div className="framework-box">


                    <h3>
                        CIS AWS Benchmark
                    </h3>


                    <strong>
                        {compliance.frameworks.CIS_AWS_Benchmark}%
                    </strong>


                </div>





                <div className="framework-box">


                    <h3>
                        NIST CSF
                    </h3>


                    <strong>
                        {compliance.frameworks.NIST_CSF}%
                    </strong>


                </div>



            </div>









            <div className="control-grid">



                <div className="control-box passed">


                    <h3>
                        ✅ Passed
                    </h3>


                    <strong>

                        {compliance.controls.passed}

                    </strong>


                </div>






                <div className="control-box failed">


                    <h3>
                        ❌ Failed
                    </h3>


                    <strong>

                        {compliance.controls.failed}

                    </strong>


                </div>



            </div>









            <div className="failed-section">


                <h3>
                    Failed Security Controls
                </h3>



                {


                compliance.failed_controls.length === 0 ?


                (

                    <p>
                        All controls passed 🎉
                    </p>

                )


                :


                compliance.failed_controls.map(
                    (item,index)=>(


                    <div
                        className="failed-item"
                        key={index}
                    >


                        <h4>
                            🔴 {item.control}
                        </h4>


                        <p>
                            Severity: {item.severity}
                        </p>


                        <span>
                            {item.recommendation}
                        </span>


                    </div>


                ))


                }



            </div>







        </div>


    );


}


export default ComplianceDashboard;