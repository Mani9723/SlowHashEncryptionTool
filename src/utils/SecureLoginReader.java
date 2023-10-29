package utils;

import scrypt.ScryptHash;

import java.io.Console;
import java.util.Scanner;

public class SecureLoginReader
{
	private static final Scanner in = new Scanner(System.in);
	public static void run()
	{
		processInput(getUsername(),getPassword());
	}

	private static void processInput(String username, String password)
	{
		if(username != null && password !=null){
			if(!username.isEmpty() && !password.isEmpty()){
				ScryptHash scryptHash = new ScryptHash(username,password);
				if(scryptHash.verifyUser()){
					System.out.println("*****Login Success!*****");
				}else{
					System.out.println("*****Invalid Credentials*****");
				}

			}
		}
	}

	private static String getUsername()
	{
		System.out.println("\t\tLogin");
		System.out.print("Username: ");
		return in.nextLine();
	}

	private static String getPassword()
	{
		String password;
		Console console = System.console();
		if(console != null) {
			// Password hiding only works in terminal environment.
			char[] passwordArray = console.readPassword("Password: ");
			return new String(passwordArray);
		}else{
			// Uses this in non-terminal environments
			System.out.print("Password: ");
			return in.nextLine();
		}
	}
}
