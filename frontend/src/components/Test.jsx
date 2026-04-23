import React, { useEffect, useState } from "react";

export default function StatCards() {
  const [stats, setStats] = useState([
    {
      title: "Total Tickets",
      value: 0,
      trend: "up",
      trendValue: "-- new tickets",
      borderColor: "border-blue-500",
      icon: (
        <svg
          className="w-14 h-14 absolute right-1 bottom-1 opacity-10"
          fill="currentColor"
          viewBox="0 0 20 20"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            fillRule="evenodd"
            d="M10 1.944A11.954 11.954 0 012.166 5C2.056 5.649 2 6.319 2 7c0 5.225 3.34 9.67 8 11.317C14.66 16.67 18 12.225 18 7c0-.682-.057-1.35-.166-2.001A11.954 11.954 0 0110 1.944zM11 14a1 1 0 11-2 0 1 1 0 012 0zm0-7a1 1 0 10-2 0v3a1 1 0 102 0V7z"
            clipRule="evenodd"
          />
        </svg>
      ),
    },
    {
      title: "Pending Tickets",
      value: 0,
      trend: "up",
      trendValue: "-- pending tickets",
      borderColor: "border-yellow-500",
      icon: (
        <svg
          className="w-14 h-14 absolute right-1 bottom-1 opacity-10"
          fill="currentColor"
          viewBox="0 0 20 20"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            fillRule="evenodd"
            d="M10 2a6 6 0 00-6 6v3.586l-.707.707A1 1 0 004 14h12a1 1 0 00.707-1.707L16 11.586V8a6 6 0 00-6-6zM10 18a3 3 0 01-3-3h6a3 3 0 01-3 3z"
            clipRule="evenodd"
          />
        </svg>
      ),
    },
    {
      title: "Urgent Tickets",
      value: 0,
      trend: "up",
      trendValue: "-- of total tickets",
      borderColor: "border-red-500",
      icon: (
        <svg
          className="w-14 h-14 absolute right-1 bottom-1 opacity-10"
          fill="currentColor"
          viewBox="0 0 20 20"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            fillRule="evenodd"
            d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z"
            clipRule="evenodd"
          />
        </svg>
      ),
    },
    {
      title: "Resolved Tickets",
      value: 0,
      trend: "down",
      trendValue: "-- resolved today",
      borderColor: "border-green-500",
      icon: (
        <svg
          className="w-14 h-14 absolute right-1 bottom-1 opacity-10"
          fill="currentColor"
          viewBox="0 0 20 20"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            fillRule="evenodd"
            d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z"
            clipRule="evenodd"
          />
        </svg>
      ),
    },
  ]);

  const [timeRange, setTimeRange] = useState("Last 24 Hours");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);

  // Fresh Service API configuration
  const FRESH_SERVICE_API = {
    BASE_URL: process.env.REACT_APP_FRESH_SERVICE_BASE_URL,
    HEADERS: {
      "Content-Type": "application/json",
      Authorization:
        "Basic " + btoa(`${process.env.REACT_APP_FRESH_SERVICE_API_KEY}:X`),
    },
  };

  // AWS Account Management - New state variables
  const [awsAccounts, setAwsAccounts] = useState([]);
  const [selectedAccount, setSelectedAccount] = useState(null);
  const [showAccountModal, setShowAccountModal] = useState(false);
  const [accountFormData, setAccountFormData] = useState({
    accountName: "",
    accessKeyId: "",
    secretKeyId: "",
  });
  const [accountError, setAccountError] = useState(null);
  const [currentUserId, setCurrentUserId] = useState(null);
  const [awsRegions, setAwsRegions] = useState([
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "af-south-1",
    "ap-east-1",
    "ap-south-1",
    "ap-northeast-3",
    "ap-northeast-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ca-central-1",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-south-1",
    "eu-west-3",
    "eu-north-1",
    "me-south-1",
    "sa-east-1",
  ]);
  const [selectedRegion, setSelectedRegion] = useState("us-east-1");

  // Lambda function URL for DynamoDB operations
  const LAMBDA_FUNCTION_URL = process.env.REACT_APP_LAMBDA_DYNAMODB;

  useEffect(() => {
    fetchFreshServiceData();
    // fetchCurrentUser();
    getCurrentUserId();
    fetchAwsAccounts();

    // Set up refresh interval (every 5 minutes)
    const intervalId = setInterval(fetchFreshServiceData, 5 * 60 * 1000);

    // Clear interval on component unmount
    return () => clearInterval(intervalId);
  }, [timeRange]); // Re-fetch when time range changes

  const getCurrentUserId = async () => {
    try {
      // This is where you would typically make an API call to get the current user
      // For example, from your authentication system (Auth0, Cognito, etc.)
      // For now, I'll use a placeholder - replace this with your actual authentication logic

      // Example: Get user from localStorage or session
      const id = sessionStorage.getItem("id");
      console.log("kk id", id);
      // return id || null;
      setCurrentUserId(id);
    } catch (err) {
      console.error("Error fetching current user:", err);
    }
  };
  const fetchFreshServiceData = async () => {
    setLoading(true);
    try {
      // Get time range filters
      const { startDate, endDate } = getTimeRangeFilter(timeRange);

      // According to Freshdesk API documentation:
      // Status values: 2 = Open, 3 = Pending, 4 = Resolved, 5 = Closed
      // Priority values: 1 = Low, 2 = Medium, 3 = High, 4 = Urgent

      // Build query parameters for all tickets - WITHOUT time filtering for total count
      let ticketsParams = new URLSearchParams({
        include: "stats",
      });

      // Make the API call to get ALL tickets (no time filter)
      const ticketsRes = await fetch(
        `${
          FRESH_SERVICE_API.BASE_URL
        }/tickets?per_page=100&${ticketsParams.toString()}`,
        {
          headers: FRESH_SERVICE_API.HEADERS,
        }
      );

      if (!ticketsRes.ok) {
        console.error("Tickets API error:", await ticketsRes.json());
        throw new Error(`Tickets API error: ${ticketsRes.status}`);
      }

      const ticketsData = await ticketsRes.json();
      console.log("Fresh Service Data:", { tickets: ticketsData });

      // Filter tickets by status
      const openTickets = ticketsData.tickets.filter(
        (ticket) => ticket.status === 2
      ).length;
      const pendingTickets = ticketsData.tickets.filter(
        (ticket) => ticket.status === 3
      ).length;
      const resolvedTickets = ticketsData.tickets.filter(
        (ticket) => ticket.status === 4
      ).length;
      const urgentTickets = ticketsData.tickets.filter(
        (ticket) => ticket.priority === 4
      ).length;

      // Count tickets resolved today
      const today = new Date().toISOString().split("T")[0];
      const resolvedToday = ticketsData.tickets.filter(
        (ticket) =>
          ticket.status === 4 &&
          new Date(ticket.updated_at).toISOString().split("T")[0] === today
      ).length;

      // Calculate percentages
      const totalTickets = ticketsData.tickets.length;
      const urgentPercentage =
        totalTickets > 0 ? Math.round((urgentTickets / totalTickets) * 100) : 0;

      // Count new tickets within the time range - apply time filter ONLY for this calculation
      const newTickets = ticketsData.tickets.filter(
        (ticket) => new Date(ticket.created_at) >= startDate
      ).length;

      // Update stats with real data
      setStats([
        {
          title: "Tickets",
          value: newTickets,
          trend: newTickets > 0 ? "up" : "down",
          trendValue: `${totalTickets} Total Tickets`,
          borderColor: "border-blue-500",
          icon: (
            <svg
              className="w-14 h-14 absolute right-1 bottom-1 opacity-10"
              fill="currentColor"
              viewBox="0 0 20 20"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                fillRule="evenodd"
                d="M10 1.944A11.954 11.954 0 012.166 5C2.056 5.649 2 6.319 2 7c0 5.225 3.34 9.67 8 11.317C14.66 16.67 18 12.225 18 7c0-.682-.057-1.35-.166-2.001A11.954 11.954 0 0110 1.944zM11 14a1 1 0 11-2 0 1 1 0 012 0zm0-7a1 1 0 10-2 0v3a1 1 0 102 0V7z"
                clipRule="evenodd"
              />
            </svg>
          ),
        },
        {
          title: "Pending Tickets",
          value: pendingTickets,
          trend: pendingTickets > totalTickets * 0.3 ? "up" : "down",
          trendValue: `${Math.round(
            (pendingTickets / totalTickets) * 100
          )}% of total`,
          borderColor: "border-yellow-500",
          icon: (
            <svg
              className="w-14 h-14 absolute right-1 bottom-1 opacity-10"
              fill="currentColor"
              viewBox="0 0 20 20"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                fillRule="evenodd"
                d="M10 2a6 6 0 00-6 6v3.586l-.707.707A1 1 0 004 14h12a1 1 0 00.707-1.707L16 11.586V8a6 6 0 00-6-6zM10 18a3 3 0 01-3-3h6a3 3 0 01-3 3z"
                clipRule="evenodd"
              />
            </svg>
          ),
        },
        {
          title: "Urgent Tickets",
          value: urgentTickets,
          trend: "up",
          trendValue: `${urgentPercentage}% of total`,
          borderColor: "border-red-500",
          icon: (
            <svg
              className="w-14 h-14 absolute right-1 bottom-1 opacity-10"
              fill="currentColor"
              viewBox="0 0 20 20"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                fillRule="evenodd"
                d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z"
                clipRule="evenodd"
              />
            </svg>
          ),
        },
        {
          title: "Resolved Tickets",
          value: resolvedTickets,
          trend: "down",
          trendValue: `${resolvedToday} resolved today`,
          borderColor: "border-green-500",
          icon: (
            <svg
              className="w-14 h-14 absolute right-1 bottom-1 opacity-10"
              fill="currentColor"
              viewBox="0 0 20 20"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                fillRule="evenodd"
                d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z"
                clipRule="evenodd"
              />
            </svg>
          ),
        },
      ]);

      // Set last updated timestamp
      setLastUpdated(new Date());
      setError(null);
    } catch (err) {
      console.error("Error fetching Fresh Service data:", err.message);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // AWS Account Management Functions

  // Fetch AWS accounts from DynamoDB via Lambda
  const fetchAwsAccounts = async () => {
    try {
      // Get the current user ID from wherever your app stores it
      // This could be from localStorage, context, state management, etc.
      const userId = sessionStorage.getItem("id"); // Implement this function based on your auth system
      console.log("naruto", userId);
      const response = await fetch(LAMBDA_FUNCTION_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          action: "getAccounts",
          userId: userId, // Pass the user ID to the backend
        }),
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch AWS accounts: ${response.status}`);
      }

      const data = await response.json();
      console.log("get accounts", data);

      if (data.accounts && data.accounts.length > 0) {
        setAwsAccounts(data.accounts);
        // Set last account as default if no account is selected
        if (!selectedAccount) {
          const lastAccount = data.accounts[data.accounts.length - 1];
          await setActiveAccount(lastAccount.credential_id);
          setSelectedAccount(lastAccount);
          setSelectedRegion(lastAccount.region || "us-east-1");
        }
      }
    } catch (err) {
      console.error("Error fetching AWS accounts:", err);
      setAccountError(err.message);
    }
  };
  // when user select account then this lambda function get triggered

  const setActiveAccount = async (accountId) => {
    try {
      // Get the current user ID
      const userId = sessionStorage.getItem("id");
      console.log("creden", accountId);
      const response = await fetch(LAMBDA_FUNCTION_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          action: "setActiveCredential",
          credential_id: accountId,
          userId: userId, // Pass the user ID
        }),
      });

      if (!response.ok) {
        throw new Error(`Failed to set active account: ${response.status}`);
      }

      console.log("Active account updated.");
    } catch (err) {
      console.error("Error setting active account:", err);
    }
  };

  // Save AWS account to DynamoDB via Lambda
  // Save AWS account to DynamoDB via Lambda
  const saveAwsAccount = async (e) => {
    if (e) e.preventDefault();
    try {
      // Validate form
      if (
        !accountFormData.accountName ||
        !accountFormData.accessKeyId ||
        !accountFormData.secretKeyId
      ) {
        setAccountError("Please fill in all required fields");
        return;
      }

      // Get the current user ID
      const userId = currentUserId;

      console.log("naruto", currentUserId);

      // Prepare data for API
      const accountData = {
        ...accountFormData,
        userId: userId,
        region: selectedRegion,
      };

      // Add email and fullName if available in session
      const email = sessionStorage.getItem("email");
      const fullName = sessionStorage.getItem("name");
      if (email) accountData.email = email;
      if (fullName) accountData.fullName = fullName;

      console.log("Saving account data:", accountData);

      // Call API to save account
      const response = await fetch(LAMBDA_FUNCTION_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          action: "saveAccount",
          account: accountData,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(
          errorData.message || `Failed to save account: ${response.status}`
        );
      }

      const result = await response.json();
      console.log("Account saved:", result);

      // Add new account to state with proper credential_id
      if (result.account) {
        const newAccount = {
          id: result.credential_id,
          credential_id: result.credential_id,
          accountName: result.account.accountName,
          region: result.account.region || selectedRegion,
          is_active: result.account.is_active || true,
        };

        setAwsAccounts([...awsAccounts, newAccount]);

        // Select the newly added account
        setSelectedAccount(newAccount);
        await setActiveAccount(newAccount.credential_id);
      }

      // Reset form and close modal
      setAccountFormData({
        accountName: "",
        accessKeyId: "",
        secretKeyId: "",
        is_active: true,
      });
      setShowAccountModal(false);
      setAccountError(null);

      // Refresh accounts list and reload page to show changes
      fetchAwsAccounts();
      window.location.reload();
    } catch (err) {
      console.error("Error saving AWS account:", err);
      setAccountError(`Failed to save account: ${err.message}`);
    }
  };

  // Handle account form input changes
  const handleAccountFormChange = (e) => {
    const { name, value } = e.target;
    setAccountFormData({
      ...accountFormData,
      [name]: value,
    });
  };

  // Handle account selection change
  const handleAccountChange = async (e) => {
    const accountId = e.target.value;
    const account = awsAccounts.find((acc) => acc.credential_id === accountId);
    console.log("acc sasuke", accountId);
    if (account) {
      setSelectedAccount(account);
      await setActiveAccount(account.credential_id);
      // Update region if account has one
      if (account.region) {
        setSelectedRegion(account.region);
      }
    }
  };

  // Handle region selection change
  const handleRegionChange = (e) => {
    const newRegion = e.target.value;
    setSelectedRegion(newRegion);

    // If an account is selected, update its region in DynamoDB
    if (selectedAccount) {
      updateAccountRegion(selectedAccount.id, newRegion);
    }
  };

  // Update account region in DynamoDB
  const updateAccountRegion = async (accountId, region) => {
    try {
      // Get the current user ID
      const userId = currentUserId;

      const response = await fetch(LAMBDA_FUNCTION_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          action: "updateAccountRegion",
          accountId,
          region,
          userId: userId, // Pass the user ID
        }),
      });

      if (!response.ok) {
        throw new Error(`Failed to update account region: ${response.status}`);
      }

      const data = await response.json();

      // Update local state with the response from the server
      if (data.account) {
        // this is account id means user id so that's why it is working fine automatically
        // so do not update this code when ever you update the credential part code
        const updatedAccounts = awsAccounts.map((acc) => {
          if (acc.id === accountId) {
            return {
              ...acc,
              region: data.account.region,
            };
          }
          return acc;
        });

        setAwsAccounts(updatedAccounts);

        // Update selected account if it's the one being modified
        if (selectedAccount && selectedAccount.credential_id === accountId) {
          setSelectedAccount({
            ...selectedAccount,
            region: data.account.region,
          });
        }
      }
    } catch (err) {
      console.error("Error updating account region:", err);
      setAccountError(err.message);
    }
  };

  // Helper function to get time range filter based on selected option
  const getTimeRangeFilter = (timeRange) => {
    const now = new Date();
    let startDate = null;

    switch (timeRange) {
      case "Last 1 Hour":
        startDate = new Date(now.getTime() - 1 * 60 * 60 * 1000);
        break;
      case "Last 6 Hours":
        startDate = new Date(now.getTime() - 6 * 60 * 60 * 1000);
        break;
      case "Last 12 Hours":
        startDate = new Date(now.getTime() - 12 * 60 * 60 * 1000);
        break;
      case "Last 24 Hours":
        startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        break;
      case "Last 7 Days":
        startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      default:
        startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    }

    return { startDate, endDate: now };
  };

  const handleTimeRangeChange = (e) => {
    setTimeRange(e.target.value);
  };

  // Format the last updated time
  const formattedLastUpdated = lastUpdated
    ? `Last updated: ${lastUpdated.toLocaleTimeString()} ${lastUpdated.toLocaleDateString()}`
    : "Updating...";

  return (
    <div className="w-full p-4">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4">
        <h1 className="text-2xl font-bold text-blue-600">
          Fresh Service Dashboard
        </h1>
        <div className="flex flex-col md:flex-row gap-4">
          {/* AWS Account Management Section */}
          <div className="flex flex-col md:flex-row gap-2">
            {/* Add AWS Account Button */}
            <button
              onClick={() => setShowAccountModal(true)}
              className="flex items-center shadow-lg justify-center px-3 py-2 bg-blue-50 hover:bg-blue-100 rounded-md border border-blue-200"
            >
              <svg
                className="w-5 h-5 mr-2"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  d="M12 6v6m0 0v6m0-6h6m-6 0H6"
                ></path>
              </svg>
              Add AWS Account
            </button>

            {/* AWS Account Dropdown */}
            <div className="relative shadow-lg ">
              <select
                className="border rounded-md px-3 py-2 pr-8 appearance-none"
                value={selectedAccount ? selectedAccount.credential_id : ""}
                onChange={handleAccountChange}
                disabled={awsAccounts.length === 0}
              >
                {awsAccounts.length === 0 && (
                  <option value="">No Accounts</option>
                )}
                {awsAccounts.map((account) => (
                  <option
                    key={account.credential_id}
                    value={account.credential_id}
                  >
                    {account.accountName}
                  </option>
                ))}
              </select>
              <div className="absolute inset-y-0 right-0 flex items-center px-2 pointer-events-none">
                <svg
                  className="w-4 h-4"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M19 9l-7 7-7-7"
                  ></path>
                </svg>
              </div>
            </div>

            {/* AWS Region Dropdown */}
            <div className="relative shadow-lg">
              <select
                className="border rounded-md px-3 py-2 pr-8 appearance-none"
                value={selectedRegion}
                onChange={handleRegionChange}
                disabled={!selectedAccount}
              >
                {awsRegions.map((region) => (
                  <option key={region} value={region}>
                    {region}
                  </option>
                ))}
              </select>
              <div className="absolute inset-y-0 right-0 flex items-center px-2 pointer-events-none">
                <svg
                  className="w-4 h-4"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M19 9l-7 7-7-7"
                  ></path>
                </svg>
              </div>
            </div>
          </div>

          {/* Time Range Selector */}
          <div className="relative shadow-lg ">
            <select
              className="border rounded-md px-3 py-2 pr-8 appearance-none"
              value={timeRange}
              onChange={handleTimeRangeChange}
            >
              <option>Last 1 Hour</option>
              <option>Last 6 Hours</option>
              <option>Last 12 Hours</option>
              <option>Last 24 Hours</option>
              <option>Last 7 Days</option>
            </select>
            <div className="absolute inset-y-0 right-0 flex items-center px-2 pointer-events-none">
              <svg
                className="w-4 h-4"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  d="M19 9l-7 7-7-7"
                ></path>
              </svg>
            </div>
          </div>

          {/* Refresh Button */}
          <button
            onClick={fetchFreshServiceData}
            className="flex items-center shadow-lg justify-center px-3 py-2 bg-purple-100 hover:bg-purple-100 rounded-md border border-purple-200"
            disabled={loading}
          >
            <svg
              className={`w-5 h-5 mr-2 ${loading ? "animate-spin" : ""}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
              ></path>
            </svg>
            {loading ? "Refreshing..." : "Refresh"}
          </button>
        </div>
      </div>

      {/* Last Updated Information */}
      <div className="mb-4 text-sm text-gray-500 flex items-center">
        <svg
          className="w-4 h-4 mr-1"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth="2"
            d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
          ></path>
        </svg>
        {formattedLastUpdated}
      </div>

      {/* AWS Account Information */}
      {selectedAccount && (
        <div className="mb-4 p-3 bg-blue-50 text-blue-700 rounded-md border border-blue-200 shadow-md">
          <div className="flex items-center">
            <svg
              className="w-5 h-5 mr-2"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              ></path>
            </svg>
            Active AWS Account:{" "}
            <span className="font-semibold mx-1">
              {selectedAccount.accountName}
            </span>{" "}
            | Region:{" "}
            <span className="font-semibold ml-1">{selectedRegion}</span>
          </div>
        </div>
      )}

      {/* Error Display */}
      {error && (
        <div className="mb-4 p-3 bg-red-50 text-red-700 rounded-md border border-red-200">
          <div className="flex items-center">
            <svg
              className="w-5 h-5 mr-2"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              ></path>
            </svg>
            Error loading data: {error}
          </div>
        </div>
      )}

      {/* AWS Account Error Display */}
      {accountError && (
        <div className="mb-4 p-3 bg-red-50 text-red-700 rounded-md border border-red-200">
          <div className="flex items-center">
            <svg
              className="w-5 h-5 mr-2"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              ></path>
            </svg>
            AWS Account Error: {accountError}
          </div>
        </div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map((stat, index) => (
          <div
            key={index}
            className={`bg-white rounded-lg shadow p-5 relative overflow-hidden border-l-4 ${stat.borderColor} hover:shadow-lg transition-shadow duration-300`}
          >
            <div className="mb-2 text-gray-600 font-medium">{stat.title}</div>
            <div className="text-4xl font-bold mb-2">
              {loading ? (
                <div className="animate-pulse h-8 w-16 bg-gray-200 rounded"></div>
              ) : (
                stat.value
              )}
            </div>
            <div
              className={`flex items-center text-sm ${
                // Only urgent and open tickets should show red when trending up
                stat.trend === "up" && (index === 0 || index === 2)
                  ? "text-red-500"
                  : stat.trend === "up" && index === 3
                  ? "text-green-500"
                  : // Pending tickets should show yellow when trending up
                  stat.trend === "up" && index === 1
                  ? "text-yellow-500"
                  : // Default colors for trending down
                  stat.trend === "down" && (index === 0 || index === 2)
                  ? "text-green-500"
                  : stat.trend === "down" && index === 3
                  ? "text-red-500"
                  : stat.trend === "down" && index === 1
                  ? "text-green-500"
                  : "text-gray-500"
              }`}
            >
              {stat.trend === "up" ? (
                <svg
                  className="w-4 h-4 mr-1"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M5 15l7-7 7 7"
                  ></path>
                </svg>
              ) : (
                <svg
                  className="w-4 h-4 mr-1"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M19 9l-7 7-7-7"
                  ></path>
                </svg>
              )}
              {loading ? (
                <div className="animate-pulse h-4 w-20 bg-gray-200 rounded"></div>
              ) : (
                stat.trendValue
              )}
            </div>
            {/* Decorative icon */}
            {stat.icon}
          </div>
        ))}
      </div>

      {/* AWS Account Modal */}
      {showAccountModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md">
            <h2 className="text-xl font-bold mb-4">Add AWS Account</h2>

            {accountError && (
              <div className="mb-4 p-3 bg-red-50 text-red-700 rounded-md border border-red-200">
                {accountError}
              </div>
            )}

            <div className="mb-4">
              <label className="block text-gray-700 text-sm font-medium mb-2">
                Account Name
              </label>
              <input
                type="text"
                name="accountName"
                value={accountFormData.accountName}
                onChange={handleAccountFormChange}
                className="w-full px-3 py-2 border rounded-md"
                placeholder="My AWS Account"
              />
            </div>

            <div className="mb-4">
              <label className="block text-gray-700 text-sm font-medium mb-2">
                Access Key ID
              </label>
              <input
                type="password"
                name="accessKeyId"
                value={accountFormData.accessKeyId}
                onChange={handleAccountFormChange}
                className="w-full px-3 py-2 border rounded-md"
                placeholder="AKIAXXXXXXXXXXXXXXXX"
              />
            </div>

            <div className="mb-4">
              <label className="block text-gray-700 text-sm font-medium mb-2">
                Secret Access Key
              </label>
              <input
                type="password"
                name="secretKeyId"
                value={accountFormData.secretKeyId}
                onChange={handleAccountFormChange}
                className="w-full px-3 py-2 border rounded-md"
                placeholder="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
              />
            </div>

            <div className="mb-4">
              <label className="block text-gray-700 text-sm font-medium mb-2">
                AWS Region
              </label>
              <select
                value={selectedRegion}
                onChange={(e) => setSelectedRegion(e.target.value)}
                className="w-full px-3 py-2 border rounded-md"
              >
                {awsRegions.map((region) => (
                  <option key={region} value={region}>
                    {region}
                  </option>
                ))}
              </select>
            </div>

            <div className="flex justify-end gap-3">
              <button
                onClick={() => {
                  setShowAccountModal(false);
                  setAccountError(null);
                  setAccountFormData({
                    accountName: "",
                    accessKeyId: "",
                    secretKeyId: "",
                  });
                }}
                className="px-4 py-2 border rounded-md hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={saveAwsAccount}
                className="px-4 py-2 bg-blue-500 text-white rounded-md hover:bg-blue-600"
              >
                Save Account
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
