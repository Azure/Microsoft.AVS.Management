> This article is not a detailed guide on how to create a pull request (PR). See [here](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/about-pull-requests) to learn more about how to work with pull requests on GitHub.

The purpose of this article is to illustrate the main checklists you must go through before a PR will be considered for inclusion in Microsoft.AVS.Management. 

These are the following checks we'll normally put in place:

0. **Accept contributor agreement**
1. **Create an issue**
   Except for small changes, alwats create an issue 1st to discuss the propsal before opening a PR. 
2. **Create Documentation**
   Every new function **must** have standard PowerShell documentation. If you modify a function and add a parameter, it **must** have associated documentation markup.
3. **Adhere to [PowerShell style guidelines](https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/required-development-guidelines?view=powershell-7.3) and [AVS Scripting guidelines](docs/README.md)**
   Format and test your code.
4. **Do NOT modify repository policies**