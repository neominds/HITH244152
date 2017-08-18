Applying source code changes and creating test environment:
========================================================================================


1. Unzip vxworks-7.zip in the directory when vxworks-7 is installed.
   e.g.  ~/media/jbabu/Windriver3/

2. Create a VSB project for SIMLINUX and create a VIP project bassed on that. 

3. Create a downloadable kernel module project. Add source file testapplications/bs.c 
   to the project and build.

4. Create a downloadable kernel module project. Add source file testapplications/bc.c 
   to the project and build.

5. Follow procedure as per example described in HITH246189_TestProcedure01.doc to 
   perform tests