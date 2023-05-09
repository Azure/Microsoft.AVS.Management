namespace AVS.Reactive
{
    public record AVSCloudSettings(string subscriptionId, string resourceGroup, string name, string packageId, string cmdlet) {
        public static AVSCloudSettings Load() {
            var subscriptionId = System.Environment.GetEnvironmentVariable("Subscription", EnvironmentVariableTarget.Process);
            var resourceGroup = System.Environment.GetEnvironmentVariable("ResourceGroup", EnvironmentVariableTarget.Process);
            var name = System.Environment.GetEnvironmentVariable("Name", EnvironmentVariableTarget.Process);
            var packageId = System.Environment.GetEnvironmentVariable("PackageId", EnvironmentVariableTarget.Process);
            var cmdlet = System.Environment.GetEnvironmentVariable("Cmdlet", EnvironmentVariableTarget.Process);
            if( subscriptionId == null || resourceGroup == null || name == null)
                throw new Exception("Cloud details not fully specified");
            if( packageId == null || cmdlet == null)
                throw new Exception("Script details not fully specified");
            return new AVSCloudSettings(subscriptionId, resourceGroup, name, packageId, cmdlet);
        } 
    } 
}