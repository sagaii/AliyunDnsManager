using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace AliyunDnsManagerCore
{
    class Program
    {
        static async Task Main(string[] args)
        {
            string action;
            string domainName;
            string value;
            string configPath;

            if (args.Length == 3)
            {
                // 通过 win-acme 调用
                action = args[0];   // "create" or "delete"
                domainName = args[1]; // The domain name (e.g., "_acme-challenge.example.com")
                value = args[2];    // The validation string for TXT record
                configPath = Path.Combine(AppContext.BaseDirectory, "appsettings.json"); // The path to appsettings.json
            }
            else if (args.Length == 0)
            {
                // 直接运行 .exe，使用默认配置添加记录
                action = "create";
                configPath = "appsettings.json"; // 默认路径
                var defaultConfig = new ConfigurationBuilder()
                    .SetBasePath(AppContext.BaseDirectory)
                    .AddJsonFile(configPath, optional: false, reloadOnChange: true)
                    .Build();

                var aliyunConfig = defaultConfig.GetSection("Aliyun");
                domainName = aliyunConfig["DomainName"] ?? throw new ArgumentNullException("DomainName", "DomainName cannot be null");
                value = aliyunConfig["RecordValue"] ?? throw new ArgumentNullException("RecordValue", "RecordValue cannot be null");
            }
            else
            {
                Console.WriteLine("Usage: AliyunDnsManagerCore <create|delete> <domain> <value> <configPath>");
                return;
            }

            // 创建配置对象
            var configuration = new ConfigurationBuilder()
                .SetBasePath(AppContext.BaseDirectory)
                .AddJsonFile(configPath, optional: false, reloadOnChange: true)
                .Build();

            // 读取阿里云配置信息
            var aliyunConfigSection = configuration.GetSection("Aliyun");
            string accessKeyId = aliyunConfigSection["AccessKeyId"] ?? throw new ArgumentNullException("AccessKeyId", "AccessKeyId cannot be null");
            string accessKeySecret = aliyunConfigSection["AccessKeySecret"] ?? throw new ArgumentNullException("AccessKeySecret", "AccessKeySecret cannot be null");

            string[] domainParts = domainName.Split(new[] { '.' }, 2);
            string rr = domainParts[0]; // "_acme-challenge"
            string mainDomain = domainParts[1]; // "example.com"

            // 处理 create 和 delete 操作
            string apiAction = action.Equals("create", StringComparison.OrdinalIgnoreCase) ? "AddDomainRecord" : "DeleteDomainRecord";
            string recordType = "TXT";

            using var client = new HttpClient();
            string requestUri;

            if (apiAction == "AddDomainRecord")
            {
                requestUri = GenerateRequestUri(accessKeyId, accessKeySecret, mainDomain, rr, recordType, value, apiAction);
            }
            else
            {
                // 删除记录时需要先查找记录的 Record ID
                string recordId = await GetRecordIdAsync(client, accessKeyId, accessKeySecret, mainDomain, rr, recordType);
                if (string.IsNullOrEmpty(recordId))
                {
                    Console.WriteLine("Record ID not found.");
                    return;
                }
                requestUri = GenerateDeleteRequestUri(accessKeyId, accessKeySecret, recordId, apiAction);
            }

            var response = await client.GetAsync(requestUri);
            var responseBody = await response.Content.ReadAsStringAsync();

            Console.WriteLine("Response:");
            Console.WriteLine(responseBody);
        }

        static string GenerateRequestUri(string accessKeyId, string accessKeySecret, string domainName, string rr, string type, string value, string action)
        {
            string format = "json";
            string version = "2015-01-09";
            string signatureMethod = "HMAC-SHA1";
            string timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            string signatureNonce = Guid.NewGuid().ToString();

            var queryParams = new SortedDictionary<string, string>
            {
                { "AccessKeyId", accessKeyId },
                { "Action", action },
                { "DomainName", domainName },
                { "Format", format },
                { "RR", rr },
                { "SignatureMethod", signatureMethod },
                { "SignatureNonce", signatureNonce },
                { "SignatureVersion", "1.0" },
                { "Timestamp", timestamp },
                { "Type", type },
                { "Value", value },
                { "Version", version }
            };

            var queryString = new StringBuilder();
            foreach (var param in queryParams)
            {
                if (queryString.Length > 0)
                {
                    queryString.Append("&");
                }
                queryString.Append($"{Uri.EscapeDataString(param.Key)}={Uri.EscapeDataString(param.Value)}");
            }

            string stringToSign = $"GET&%2F&{Uri.EscapeDataString(queryString.ToString())}";
            string signature = GenerateSignature(stringToSign, accessKeySecret);

            return $"https://alidns.aliyuncs.com/?{queryString}&Signature={Uri.EscapeDataString(signature)}";
        }

        static string GenerateDeleteRequestUri(string accessKeyId, string accessKeySecret, string recordId, string action)
        {
            string format = "json";
            string version = "2015-01-09";
            string signatureMethod = "HMAC-SHA1";
            string timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            string signatureNonce = Guid.NewGuid().ToString();

            var queryParams = new SortedDictionary<string, string>
            {
                { "AccessKeyId", accessKeyId },
                { "Action", action },
                { "Format", format },
                { "RecordId", recordId },
                { "SignatureMethod", signatureMethod },
                { "SignatureNonce", signatureNonce },
                { "SignatureVersion", "1.0" },
                { "Timestamp", timestamp },
                { "Version", version }
            };

            var queryString = new StringBuilder();
            foreach (var param in queryParams)
            {
                if (queryString.Length > 0)
                {
                    queryString.Append("&");
                }
                queryString.Append($"{Uri.EscapeDataString(param.Key)}={Uri.EscapeDataString(param.Value)}");
            }

            string stringToSign = $"GET&%2F&{Uri.EscapeDataString(queryString.ToString())}";
            string signature = GenerateSignature(stringToSign, accessKeySecret);

            return $"https://alidns.aliyuncs.com/?{queryString}&Signature={Uri.EscapeDataString(signature)}";
        }

        static async Task<string> GetRecordIdAsync(HttpClient client, string accessKeyId, string accessKeySecret, string domainName, string rr, string type)
        {
            string action = "DescribeDomainRecords";
            string format = "json";
            string version = "2015-01-09";
            string signatureMethod = "HMAC-SHA1";
            string timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            string signatureNonce = Guid.NewGuid().ToString();

            var queryParams = new SortedDictionary<string, string>
            {
                { "AccessKeyId", accessKeyId },
                { "Action", action },
                { "DomainName", domainName },
                { "Format", format },
                { "SignatureMethod", signatureMethod },
                { "SignatureNonce", signatureNonce },
                { "SignatureVersion", "1.0" },
                { "Timestamp", timestamp },
                { "Version", version },
                { "RRKeyWord", rr },
                { "Type", type }
            };

            var queryString = new StringBuilder();
            foreach (var param in queryParams)
            {
                if (queryString.Length > 0)
                {
                    queryString.Append("&");
                }
                queryString.Append($"{Uri.EscapeDataString(param.Key)}={Uri.EscapeDataString(param.Value)}");
            }

            string stringToSign = $"GET&%2F&{Uri.EscapeDataString(queryString.ToString())}";
            string signature = GenerateSignature(stringToSign, accessKeySecret);

            string requestUri = $"https://alidns.aliyuncs.com/?{queryString}&Signature={Uri.EscapeDataString(signature)}";

            var response = await client.GetAsync(requestUri);
            var responseBody = await response.Content.ReadAsStringAsync();

            if (string.IsNullOrEmpty(responseBody))
            {
                Console.WriteLine("Response body is null or empty.");
                return string.Empty;
            }

            dynamic jsonResponse = Newtonsoft.Json.JsonConvert.DeserializeObject(responseBody ?? string.Empty);

            if (jsonResponse != null &&
                jsonResponse!.DomainRecords != null &&
                jsonResponse!.DomainRecords.Record != null &&
                jsonResponse!.DomainRecords.Record.Count > 0)
            {
                return jsonResponse.DomainRecords.Record[0]?.RecordId?.ToString() ?? string.Empty;
            }

            Console.WriteLine("No valid records found in the response.");
            return string.Empty;
        }

        static string GenerateSignature(string stringToSign, string accessKeySecret)
        {
            using (var hmac = new HMACSHA1(Encoding.UTF8.GetBytes(accessKeySecret + "&")))
            {
                var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign));
                return Convert.ToBase64String(hash);
            }
        }
    }
}
