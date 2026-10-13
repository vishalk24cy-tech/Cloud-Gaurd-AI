import { useEffect, useState } from "react";
import api from "../services/api";
import "./Notifications.css";


function Notifications(){

    const [notifications,setNotifications] = useState([]);
    const [open,setOpen] = useState(false);


    useEffect(()=>{

        loadNotifications();

    },[]);



    const loadNotifications = async()=>{

        try{

            const res = await api.get("/notifications/");

            setNotifications(res.data || []);

        }
        catch(err){

            console.log(
                "Notification error",
                err
            );

        }

    };



    const readNotification = async(id)=>{

        try{

            await api.put(
                `/notifications/read/${id}`
            );


            loadNotifications();

        }
        catch(err){

            console.log(err);

        }

    };



    return(

        <div className="notification-wrapper">


            <button
                className="notification-btn"
                onClick={()=>setOpen(!open)}
            >

                🔔


                {
                    notifications.length > 0 &&

                    <span className="notification-count">

                        {notifications.length}

                    </span>

                }


            </button>



            {
                open &&

                <div className="notification-panel">


                    <h3>
                        Security Alerts
                    </h3>



                    {

                    notifications.length === 0 ?

                    (

                        <p className="no-alert">

                            No new alerts 🎉

                        </p>

                    )

                    :

                    notifications.map((item)=>(


                        <div

                        key={item._id}

                        className="notification-item"

                        onClick={()=>readNotification(item._id)}

                        >


                            <strong>

                                {item.title}

                            </strong>


                            <p>

                                {item.message}

                            </p>


                            <small>

                                {item.severity}

                            </small>


                        </div>


                    ))

                    }


                </div>

            }


        </div>

    );

}


export default Notifications;