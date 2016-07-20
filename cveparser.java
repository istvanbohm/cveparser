package hu.istvan.bohm.cveparser;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringEscapeUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;

public class cveparser {

	public static final String RAW_URL = "http://cve.mitre.org/cgi-bin/cvename.cgi?name=%s";
	public static final String CSS_DESC_TABLE_ROW= "html body div#Page table tbody tr td div#GeneratedTable table tbody tr";
	
	public static void main(String[] args) {
		
		List<String> cveList = new ArrayList<String>();
		try(BufferedReader br = new BufferedReader(new FileReader("cve_list.txt"))) {	
		    String line = br.readLine();
		    while (line != null) {
		    	cveList.add(line.trim());
		        line = br.readLine();
		    }
		} catch (FileNotFoundException e2) {
			System.err.println("Error: Could not read the input file: cve_list.txt.");
			System.exit(1);
		} catch (IOException e) {
			System.err.println("Error: IOException while reading from the input file: cve_list.txt.");
			System.exit(1);
		}
		
		PrintWriter writer;
		try {
			writer = new PrintWriter("cve_result.html", "UTF-8");
			
			writer.println("<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">");
			writer.println("<html>"); 
			writer.println("<head>"); 
			writer.println("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">"); 
			writer.println("    <title>CVE LIST</title>"); 
			writer.println("</head>");
			writer.println("<body>"); 
			writer.println("    <table>"); 

			for(String cve : cveList) {
				String url = String.format(RAW_URL,cve);
				writer.println("        <tr>"); 
				writer.println("            <td><a href=\""+url+"\">"+cve+"</a></td>"); 
				String result = "N/A";
				Document doc;
				try {
					doc = Jsoup.connect(url).get();
					Elements eDescTable = doc.select(CSS_DESC_TABLE_ROW);
					int size = eDescTable.size();
					int i=0;
					for(;i<size;++i) {
						String data = eDescTable.get(i).text();
						if(data.equals("Description") && i+1<size) {
							result = eDescTable.get(i+1).text();
						}
					}
				} catch (IOException e) {
					System.err.println("Error: Could not download html: " + url + ".");
				}
				writer.println("            <td>"+StringEscapeUtils.escapeHtml4(result)+"</td>");
				writer.println("        </tr>");
			}
			
			writer.println("    </table>");
			writer.println("</body>");
			writer.println("</html>");
			writer.close();
			
		} catch (FileNotFoundException e1) {
			System.err.println("Error: Could not create output file: cve_result.html.");
			System.exit(1);
		} catch (UnsupportedEncodingException e1) {
			System.err.println("Error: UTF8 is not supported.");
			System.exit(1);
		}
	}

}
