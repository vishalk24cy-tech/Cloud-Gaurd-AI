import { useState } from "react";
import { Bot, Copy, Send, Sparkles, X } from "lucide-react";
import api from "../services/api";
import "./AIChatWidget.css";


function AIChatWidget() {


const [open,setOpen]=useState(false);

const [question,setQuestion]=useState("");

const [loading,setLoading]=useState(false);


const [messages,setMessages]=useState([
{
type:"ai",
text:
"Welcome to CloudGuardAI Security Copilot.\n\nAsk about AWS security, IAM, S3, EC2, VPC, Terraform, compliance, or cloud risk."
}
]);



const escapeHTML=(str)=>{
return str
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;")
  .replace(/'/g, "&#039;");
};

const formatMessage=(text)=>{
return escapeHTML(text)
.replace(/\*\*(.*?)\*\*/g,"<strong>$1</strong>")
.replace(/\n/g,"<br/>");
};



const copyMessage=(text)=>{

navigator.clipboard.writeText(text);

alert("Copied!");

};




const sendMessage=async()=>{


if(!question.trim()) return;


const userQuestion=question;


setMessages(prev=>[
...prev,
{
type:"user",
text:userQuestion
}
]);



setQuestion("");

setLoading(true);



try{


const res=await api.post(
"/ai/chat",
{
question:userQuestion
}
);



setMessages(prev=>[
...prev,
{
type:"ai",
text:res.data.answer
}
]);


}

catch(err){


setMessages(prev=>[
...prev,
{
type:"ai",
text:"❌ AI service unavailable."
}
]);


}


setLoading(false);


};




return(

<>


<button

className="ai-floating-btn"

onClick={()=>setOpen(!open)}

>

<Bot size={22} />

</button>





{
open &&

<div className="ai-chat-window">



<div className="ai-chat-header">


<div>

<h3>
<Sparkles size={16} /> CloudGuardAI
</h3>


<p>
AI Security Analyst
</p>

</div>



<button
onClick={()=>setOpen(false)}
>
<X size={16} />
</button>


</div>





<div className="ai-messages">


{
messages.map((msg,index)=>(


<div

key={index}

className={
msg.type==="user"
?
"user-message"
:
"ai-message"
}

>


<div

dangerouslySetInnerHTML={{
__html:formatMessage(msg.text)
}}

>



</div>



{
msg.type==="ai" &&

<button

className="copy-message"

onClick={()=>copyMessage(msg.text)}

>

<Copy size={13} /> Copy

</button>

}



</div>


))

}




{
loading &&

<div className="thinking">

<span className="ai-activity-dot" /> AI is analyzing security context...

</div>

}



</div>







<div className="ai-input-area">


<input

value={question}

onChange={
e=>setQuestion(e.target.value)
}

onKeyDown={
e=>{
if(e.key==="Enter")
sendMessage()
}
}

placeholder="Ask Cloud Security question..."

/>


<button

onClick={sendMessage}

>

<Send size={14} /> Send

</button>


</div>



</div>


}



</>


);


}


export default AIChatWidget;