using Azure.ResourceManager.Avs.Models;
using Azure.Core;
using Azure.ResourceManager.Avs;
using Azure;

namespace AVS.Reactive
{
    public static class ScriptExecution
    {
        public static Task<Azure.ResourceManager.ArmOperation<ScriptExecutionResource>> Run(AvsPrivateCloudResource avsCloud, string name, ResourceIdentifier cmdletId, params ScriptExecutionParameterDetails[] parameters) {
            var data = new ScriptExecutionData {
                ScriptCmdletId = cmdletId,
                Retention = System.Xml.XmlConvert.ToString(TimeSpan.FromMinutes(10)),
                Timeout = System.Xml.XmlConvert.ToString(TimeSpan.FromMinutes(10))
            };
            foreach(var p in parameters) data.Parameters.Add(p);
            return avsCloud.GetScriptExecutions().CreateOrUpdateAsync(WaitUntil.Completed, name, data);
        }
    }
}
