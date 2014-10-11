package com.sample.bigquery;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeRequestUrl;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson.JacksonFactory;
import com.google.api.client.util.Data;
import com.google.api.services.bigquery.Bigquery;
import com.google.api.services.bigquery.BigqueryScopes;
import com.google.api.services.bigquery.model.GetQueryResultsResponse;
import com.google.api.services.bigquery.model.QueryRequest;
import com.google.api.services.bigquery.model.QueryResponse;
import com.google.api.services.bigquery.model.TableCell;
import com.google.api.services.bigquery.model.TableRow;

public class BigQueryAnalytics {

	private static final String PROJECT_ID = "113328801072";
	private static final String CLIENTSECRETS_LOCATION = "client_secrets.json";
	private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();
	private static final JsonFactory JSON_FACTORY = new JacksonFactory();

	public static void main(String[] args) throws IOException {
		String filePath = System.getProperty("user.dir") + "\\src\\" + CLIENTSECRETS_LOCATION;
		InputStream inputStream = new FileInputStream(filePath);
		InputStreamReader stReader = new InputStreamReader(inputStream);
		GoogleClientSecrets clientSecrets = GoogleClientSecrets.load(
				new JacksonFactory(), stReader);

		Credential credential = getCredentials(clientSecrets, new Scanner(
				System.in));

		Bigquery bigquery = new Bigquery(HTTP_TRANSPORT, JSON_FACTORY,
				credential);
		String query = "SELECT TOP( title, 10) as title, COUNT(*) as revision_count "
				+ "FROM [publicdata:samples.wikipedia] WHERE wp_namespace = 0;";
		runQueryRpcAndPrint(bigquery, PROJECT_ID, query, System.out);
	}

	static Credential getCredentials(GoogleClientSecrets clientSecrets,
			Scanner scanner) throws IOException {
		String authorizeUrl = new GoogleAuthorizationCodeRequestUrl(
				clientSecrets, clientSecrets.getInstalled().getRedirectUris()
						.get(0), Collections.singleton(BigqueryScopes.BIGQUERY))
				.build();
		System.out
				.println("Paste this URL into a web browser to authorize BigQueryAnalysisAnalysis Access:\n"
						+ authorizeUrl);
		System.out.println("... and paste the code you received here: ");
		String authorizationCode = scanner.nextLine();

		// Exchange the auth code for an access token.
		GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
				HTTP_TRANSPORT, JSON_FACTORY, clientSecrets,
				Arrays.asList(BigqueryScopes.BIGQUERY)).build();
		GoogleTokenResponse response = flow
				.newTokenRequest(authorizationCode)
				.setRedirectUri(
						clientSecrets.getInstalled().getRedirectUris().get(0))
				.execute();
		return flow.createAndStoreCredential(response, null);
	}

	static void runQueryRpcAndPrint(Bigquery bigquery, String projectId,
			String query, PrintStream out) throws IOException {
		QueryRequest queryRequest = new QueryRequest().setQuery(query);
		QueryResponse queryResponse = bigquery.jobs()
				.query(projectId, queryRequest).execute();
		if (queryResponse.getJobComplete()) {
			printRows(queryResponse.getRows(), out);
			if (null == queryResponse.getPageToken()) {
				return;
			}
		}
		// This loop polls until results are present, then loops over result
		// pages.
		String pageToken = null;
		while (true) {
			GetQueryResultsResponse queryResults = bigquery
					.jobs()
					.getQueryResults(projectId,
							queryResponse.getJobReference().getJobId())
					.setPageToken(pageToken).execute();
			if (queryResults.getJobComplete()) {
				printRows(queryResults.getRows(), out);
				pageToken = queryResults.getPageToken();
				if (null == pageToken) {
					return;
				}
			}
		}
	}

	private static void printRows(List<TableRow> rows, PrintStream out) {
		if (rows != null) {
			for (TableRow row : rows) {
				for (TableCell cell : row.getF()) {
					out.printf("%s, ", Data.isNull(cell.getV()) ? "null" : cell
							.getV().toString());
				}
				out.println();
			}
		}
	}
	
	public static void disableCertificateValidation() {
    // Create a trust manager that does not validate certificate chains
    TrustManager[] trustAllCerts = new TrustManager[] {new X509TrustManager() {
      public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
      }

      public void checkClientTrusted(X509Certificate[] certs, String authType) {}

      public void checkServerTrusted(X509Certificate[] certs, String authType) {}
    }};

    // Ignore differences between given hostname and certificate hostname
    HostnameVerifier hv = new HostnameVerifier() {
      public boolean verify(String hostname, SSLSession session) {
        return true;
      }
    };

    // Install the all-trusting trust manager
    try {
      SSLContext sc = SSLContext.getInstance("SSL");
      sc.init(null, trustAllCerts, new SecureRandom());
      HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
      HttpsURLConnection.setDefaultHostnameVerifier(hv);
    } catch (Exception e) {
    }
  }

}