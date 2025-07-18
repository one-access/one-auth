package com.oneaccess.auth.springcustomizedstarterexample.utils.exceptions;

public class ResourceNotFoundException extends RuntimeException
{

	public ResourceNotFoundException() { }

	public ResourceNotFoundException(String message)
	{
		super(message);
	}

	public ResourceNotFoundException(String message, Throwable cause)
	{
		super(message, cause);
	}

	public ResourceNotFoundException(Throwable cause)
	{
		super(cause);
	}
}
