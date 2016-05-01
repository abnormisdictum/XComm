package org.structure;

import org.apache.commons.math3.random.RandomDataGenerator;

public class MovingFactor 
{
	private long a,b,c;
	
	private static long pow(long x, long p)
	{
		return Math.round(Math.pow(x, p));
	}
	
	public MovingFactor()
	{
		RandomDataGenerator rdg = new RandomDataGenerator();
		a = rdg.nextLong(-1000, 1000);
		b = rdg.nextLong(-1000, 1000);
		c = rdg.nextLong(-1000, 1000);
	}
	
	public long getMovingFactor(long msg_no)
	{
		long ret = a*pow(-1, msg_no)*pow(msg_no, 5)+b*pow(-1, msg_no+1)*pow(msg_no, 3)+c*pow(msg_no, 2)-a*b*c*msg_no;
		return ret;
	}
}
