def check_config(config_client):

    findings = []


    try:


        # Check AWS Config recorder status

        recorders = config_client.describe_configuration_recorders()


        recorder_list = recorders.get(
            "ConfigurationRecorders",
            []
        )



        if len(recorder_list) == 0:


            findings.append({

                "service":
                "AWS Config",

                "severity":
                "HIGH",

                "issue":
                "AWS Config Recorder Not Enabled",

                "status":
                "Failed",

                "recommendation":
                "Enable AWS Config recorder to monitor resource compliance."

            })


        else:


            status = config_client.describe_configuration_recorder_status()


            recorder_status = status.get(
                "ConfigurationRecordersStatus",
                []
            )



            enabled = False


            for item in recorder_status:


                if item.get(
                    "recording"
                ):

                    enabled = True




            if enabled:


                findings.append({

                    "service":
                    "AWS Config",

                    "severity":
                    "LOW",

                    "issue":
                    "AWS Config Recording Enabled",

                    "status":
                    "Protected",

                    "recommendation":
                    "No action required."

                })


            else:


                findings.append({

                    "service":
                    "AWS Config",

                    "severity":
                    "HIGH",

                    "issue":
                    "AWS Config Recording Disabled",

                    "status":
                    "Failed",

                    "recommendation":
                    "Start AWS Config recorder."

                })





        # Compliance Rules Check


        rules = config_client.describe_config_rules()


        config_rules = rules.get(
            "ConfigRules",
            []
        )



        if len(config_rules) == 0:


            findings.append({

                "service":
                "AWS Config",

                "severity":
                "MEDIUM",

                "issue":
                "No Compliance Rules Configured",

                "status":
                "Failed",

                "recommendation":
                "Create CIS benchmark compliance rules."

            })



        else:


            findings.append({

                "service":
                "AWS Config",

                "severity":
                "LOW",

                "issue":
                f"{len(config_rules)} Compliance Rules Active",

                "status":
                "Protected",

                "recommendation":
                "Continue monitoring compliance."

            })




    except Exception as e:


        findings.append({

            "service":
            "AWS Config",

            "severity":
            "MEDIUM",

            "issue":
            "AWS Config Scan Failed",

            "status":
            "Unknown",

            "recommendation":
            str(e)

        })



    return findings