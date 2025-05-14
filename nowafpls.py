# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory, IHttpListener, IRequestInfo, IContextMenuInvocation
from javax.swing import JMenuItem, JLabel, JTextField, JOptionPane, JPanel, JFrame
import javax.swing as swing
from java.util import ArrayList
from java.io import ByteArrayOutputStream
import re
import random
import string

class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("burp-nowafpls")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)

    def createMenuItems(self, invocation):
        self.context = invocation
        menu_list = ArrayList()
        if self.context.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            menu_list.add(JMenuItem("Insert Junk Data Size", actionPerformed=self.insert_random_data))
            menu_list.add(JMenuItem("Insert double Content-Length", actionPerformed=self.insert_double_content_length))
            menu_list.add(JMenuItem("Confuse WAF ignore CL", actionPerformed=self.confuse_waf_ignore_cl))
            menu_list.add(JMenuItem("Confuse WAF ignore TE", actionPerformed=self.confuse_waf_ignore_te))
            menu_list.add(JMenuItem("Chunk body in X blocks", actionPerformed=self.chunk_body_x_blocks))
            menu_list.add(JMenuItem("Chunk body in 2 blocks (invalid)", actionPerformed=self.chunk_body_2_blocks))
        return menu_list

    def generate_random_string(self, length, charset=None):
        if charset is None:
            charset = string.ascii_letters + string.digits + "-_"
        return ''.join(random.choice(charset) for _ in range(length))

    def generate_random_param(self):
        prefixes = ['id', 'user', 'session', 'token', 'auth', 'request', 'data', 'temp', 'cache', 'author','authorID','authorName','authorityType','authorize','authorized','authorizedkeys','authors','authorship','authserver','authtype','auto','autoaddfields','autoadjust','autoapprove','autoassign','autocomplete','autodel','autodeltime','autoedge','autoenable','autofix','autofixforcedest','autofixforcesource','autofocus','autogroup','autologin','automatic','autoplay','autoptp','autoredirect','autorefresh','autosave','autoupdate','avatar','avatars','b','bID','baba','back','backcconnmsg','backcconnmsge','backconnectport','backdrop','backend','background','backto','backup','backuparea','backupbeforeupgrade','backupcount','backupnow','backuptype','backurl','baddress1','baddress2','badfiles','balance','ban','bandwidth','banid','banip','bank','banned','bannedUser','banner','banreason','bansubmit','bantime','bantype','bar','barcode','base','base64','basedn','basemodule','baseurl','basic','basket','baslik','batch','batchExtend','batchID','baz','baza','bbc','bbconfigloc','bbox','bcc','bcip','bcity','bconfirmemail','bcountry','bday2','bduss','be','before','begin','beginner','behaviour','bemail','benchmark','beta','bfirstname','bg','bgColor','bgc','bgcolor','bi','bib','biblioID','biblioTitle','bid','bill','billing','binary','binddn','binding','bindip','bindpw','bio','bip','birth','birthDate','birthdate','birthday','birthmonth','birthplace','birthyear','bitrate','bits','blacklist','blastname','blatent','block','blockbogons','blockedafter','blockedmacsurl','blockeduntil','blockid','blocklabel','blockpriv','blocks','blog','blogbody','blogid','blogname','blogs','blogtags','blogtitle','blogusers','board','boardaccess','boardid','boardmod','boardprofile','boards','boardseen','boardtheme','boardurl','body','bodytext','bogonsinterval','bomb','bonus','book','bookings','bookmark','bool','boolean','bootslice','bootstrap','border','bots','bottom','bounce','box','box1','box2','box3','boxes','bpage','bpg','bphone','bport','bps','branch','brand','brd','breadcrumb','break','breakdown','breakpoint','breakpoints','bridge','bridgeif','broadcast','broken','browse','browser','bs','bstate','btn','btnSubmit','bucket','buddies','budget','bug','build','bulk','bulletin','business','businessName','button','buttons','buttonval','buy','bv','bwdefaultdn','bwdefaultup','by','byapache','bycw','bye','byetc','byfc','byfc9','byoc','bypassstaticroutes','bypcu','bysyml','bythis','byws','bzipcode','c','c2','c37url','c99shcook','cID','cP','cPath','cable','cache','cacheable','cached','caching','caid','cainfo','cal','calcolor','calendar','calendarid','calid','call','callNumber','callback','callbackPW','caller','callerId','callerid','callf','callop','calname','cambio','campaign','campaignid','campo','cancel','canceldelete','cancelled','caneditdomain','caneditphpsettings','canned','canpreview','cantidad','canvas','cap','captcha','caption','capture','card','cardno','cardtype','caref','cart','cartId','case','casein','cat','catID','catId','catalogName','catalogid','categories','category','categoryID','categoryName','categoryid','categoryname','cateid','catid','catname','catorder','cats','catslist','cb','cc','cd','cdir','cdirname','cdone','cds','censorIgnoreCase','censorWholeWord','censortest','censortext','cep','cert','certdepth','certid','certificate','certref','certsubject','cf','cfed','cfg','cfgkey','cfgval','cfil','cfile','cfilename','cfx','cfy','ch','challenge','chan','change','changePass','changeUserGroup','changeVisitAlpha','changecurrent','changed','changeit','changepassword','changero','changes','changestatus','changeusername','chanid','channel','channelID','channelName','channelmode','channels','chapo','chapter','char','characterid','characters','charge','chars','charset','charsout','chart','chartSettings','chartsize','chat','chatmsg','chats','chdir','check','check1','checkReshare','checkShares','checkaliasesurlcert','checkbox','checkboxes','checkconnect','checked','checkemail','checkid','checking','checkmetadesc','checknum','checkout','checkprivsdb','checkprivstable','checksum','checksumbits','chfl','child','children','chk','chkagree','chkalldocs','chm','chmod','chmod0','chmodenum','chmodnow','choice','choice2','choix','chosen','chpage','chromeless','chunk','chunks','chvalue','cid','cids','cinterface','cipher','city','ck','ckeditor','cktime','cl','claim','class','classOptions','classification','classname','clay','clean','cleancache','cleanup','clear','clearLog','clearLogs','clearSess','clearcache','cleared','clearlogs','clearquery','clearsql','cleartokens','cli','clicked','clickedon','client','clientId','clientcookies','clientid','clipboard','clockstats','clone','close','closed','closedate','closenotice','cls','cluster','cm','cmd','cmde','cmdex','cmdid','cmdir','cmdr','cmediafix','cmmd','cmode','cms','cmsadmin','cmsadminemail','cmspassword','cmspasswordconfirm','cn','cname','cnpj','co','coM','coauthors','cod','code','codeblock','coded','codepress','codes','codetype','coin','col','colName','collType','collTypeID','collTypeName','collapse','collation','collectcolumn','collection','collectionfrom','collectionto','college','colltype','color','color1','color2','colors','colours','cols','column','columnIndex','columns','columnsToDisplay','com','combine','combo','command','commander','comment','commentId','commentaire','commentid','comments','commenttext','commex','commit','commits','commonName','communication','community','comp','compact','company','compare','complete','completed','component','compose','compr','compress','compression','con','concepto','condition','conditions','conf','config','configfile','configs','configuration','configure','confirm','confirm2','confirm3','confirmEmail','confirmFinish','confirmPassword','confirmation','confirmdelete','confirmed','confirmpassword','conflict','conn','connect','connectback','connection','connectionType','connections','connectt','connport','connsub','consent','consoleview','const','constraint','consumer','consumerKey','consumerSecret','cont','contact','contactEmail','contactID','contactId','contactName','contactid','contactidlist','contactname','contacts','container','containerid','contains','contbutt','content','content1','contentDesc','contentPath','contentTitle','contentType','contents','contenttype','contest','context','continue','control','controller','controllers','conv','conversation','convert','convertmode','cookie','cookielength','cookiename','cookies','coord','coords','cop','copied','coppa','coppaFax','coppaPost','copy','copyname','copyright','core','correctcase','cost','count','counter','countonly','country','countryCode','countryID','countryName','counts','coupling','coupon','couponamount','couponcode','course','courseId','courses','cover','coverage','cp','cpage','cpass','cpath','cpu','cpw','cpy','cpyto','cr','cracK','crannycap','crcf','crdir','cre','create','createaccount','createclass','created','createdb','createdon','createfolder','createlist','createmode','createpages','createstdsubdomain','createuser','createview','credentials','credit','creditCardNumber','creditCardType','credits','crefile','criteria','criteriaAndOrColumn','criteriaAndOrRow','criteriaColumn','criteriaColumnAdd','criteriaColumnCollations','criteriaColumnCount','criteriaColumnDelete','criteriaColumnInsert','criteriaColumnName','criteriaColumnNames','criteriaColumnOperators','criteriaColumnTypes','criteriaRowAdd','criteriaRowDelete','criteriaRowInsert','criteriaSearchString','criteriaSearchType','criteriaShow','criteriaSort','criteriaTables','criteriaValues','cron','crop','cropDetails','crrt','crt','crtty','crypo','crypt','cs','cs1','cs2','csid','csr','csrf','csrftoken','css','csspreview','csv','csvIDs','ct','ctag','ctf','ctid','ctrl','ctx','ctype','cuenta','cur','curdir','curfile','curl','curpage','curpath','curr','currency','currencyCode','currencyCodeType','currencyid','current','currentFolder','currentFolderPath','currentPage','currentPassword','currentday','currentid','cursor','cust','custid','custom','customFieldId','customId','customWhereClause','customaddtplid','customcss','customer','customerid','customernumber','customers','customfield','customized','cut','cvmodule','cvv','cvv2Number','cw','cx','cy','d','d1','d2','dB','dID','daemon','dare','darezz','dashboard','data','data2','dataLabel','dataType','dataangle','database','databasehost','databaseloginname','databaseloginpassword','databasename','databases','datadir','dataflt','datagapangle','datagapradius','dataofs','dataroot','dataset','datasrt','datatype','dataurl','date','date1','date2','dateEnd','dateExpected','dateFormat','dateReceived','dateStart','datechange','dateformat','datefrom','dates','datestamp','datetime','dateto','datetype','day','dayDelta','dayname','days','db','dbHost','dbName','dbOP','dbPass','dbPassword','dbPort','dbPrefix','dbPwd','dbTablePrefix','dbType','dbUser','dbUsername','dbase','dbbase','dbg','dbh','dbhost','dbid','dbms','dbn','dbname','dbp','dbpass','dbpassword','dbport','dbprefix','dbpw','dbserver','dbsession','dbsize','dbsocket','dbstats','dbtype','dbu','dbuser','dbusername','dc','dccharset','dd','ddnsdomain','ddnsdomainkey','ddnsdomainkeyname','ddnsdomainprimary','ddnsupdate','ddo','deL','deS','deact','deactivate','deactivated','deadfilescheck','deadline','deathdate','deathplace','debet','debit','debug','debug2','debug3','debugbox','debugfailover','debugmethods','decline','decode','decoded','decomposition','decrypt','deduction','def','default','defaultValue','defaultgw','defaultleasetime','defaultqueue','defaults','defaulttemplate','deftime','degrees','del','delName','delall','delay','deld','deldat','deldir','delete','deleteAccount','deleteCategory','deleteImage','deleteImages','deleteIndex','deleteList','deletePrices','deleteUser','deleteUserGroup','deleteUsers','deleteall','deletebookmarks','deletecheck','deletecntlist','deletecomment','deleted','deletedSpecs','deletedir','deleteevent','deletefile','deletefolder','deleteg','deletegrp','deleteid','deleteip','deletemeta','deletepage','deletepms','deletepost','deleterule','deletesmiley','deletesubmit','deleteuser','deleteweek','delf','delfbadmin','delfile','delfl','delfolder','delfriend','delgroup','delid','delim','delimeter','delimiter','deliver','deliveries','delivery','delmac','delmarked','delpref','delregname','delrow','delrule','delsel','delstring','delsub','deltpl','deltype','deluser','demo','demoData','demolish','dend','denied','deny','denyunknown','department','depid','deposit','dept','depth','deptid','depts','des','desact','desc','desc1','desc2','descending','descr','descripcion','description','design','dest','destd','destination','destino','destslice','detached','detail','detail0','details','dev','device','deviceid','devid','df','dfilename','dfrom','dhcp','dhcp6prefixonly','dhcp6usev4iface','dhcpbackup','dhcpfirst','dhcphostname','dhcpleaseinlocaltime','dhcprejectfrom','dhcpv6leaseinlocaltime','dhtc','dialog','dict','dictionary','did','dif','diff','difficulty','dig','digest','dim','dimensions','dip','dipl','dir','dirList','dirToken','diract','dircreate','dire','direccion','direct','direction','directmode','director','directory','directoryscanner','dirfree','dirlisting','dirname','dirr','dirs','dirupload','dis','disable','disablebeep','disablecarp','disablecheck','disablechecksumoffloading','disableconsolemenu','disabled','disabledBBC','disablefilter','disablehttpredirect','disablelargereceiveoffloading','disablelocallogging','disablenegate','disablereplyto','disablescrub','disablesegmentationoffloading','disablevpnrules','disallow','disapprove','discard','discipline','discount','disk','diskspace','dismiss','disp','display','displayAllColumns','displayName','displayVisualization','displayname','distance','distinct','distribution','div','diversity','divider','dizin','dkim','dl','dl2','dlPath','dlconfig','dldone','dlgzip','dlt','dm','dmodule','dn','dname','dnpipe','dns1','dns2','dns3','dns4','dnsallowoverride','dnslocalhost','dnsquery','dnssec','dnssecstripped','dnssrcip','do','doDelete','doExport','doImport','doRegister','doSearch','doaction','doaction2','dob','doc','docgroup','docgroups','docid','docroot','docs','doctype','document','documentID','documentgroup','documentroot','doi','doimage','doinstall','doit','dolma','domaiN','domain','domainname','domains','domainsearchlist','domen','domerge','donated','done','donor','donotbackuprrd','dontFormat','dontlimitchars','dopt','dos','dosearch','dosthisserver','dosyaa','down','downchange','downf','downloaD','download','downloadIndex','downloadbackup','downloadbtn','downloaded','downloadid','downloadpos','dp','dpath','dpgn','draft','dragdroporder','dragtable','drilldown','driver','drop','dropped','droptables','dry','dryrun','dscp','dst','dstbeginport','dstendport','dstip','dstmask','dstnot','dstport','dsttype','dt','dtend','dto','dtstart','due','duedate','duid','dumd','dummy','dump','dup','dupfiles','duplicate','duration','dwld','dxdir','dxdirsimple','dxfile','dximg','dxinstant','dxmode','dxparam','dxportscan','dxsqlsearch','dxval','dynamic','e','ealgo','ec','echostr','ecotax','ecraz','ed','eday','edge','edit','editParts','editUserGroup','editUserGroupSubmit','editable','editaction','edited','editedon','editf','editfile','editfilename','editform','editgroup','editid','editing','edition','editkey','editor','editprofile','edittxt','edituser','editwidget','education','ee','ef','eheight','eid','eids','elastic','element','elementId','elementType','elements','em','email','email1','email2','emailActivate','emailAddress','emailBody','emailID','emailId','emailList','emailToken','emailaddress','emailch','emailcomplete','emailfrom','emailnotif','emails','emailsubject','emailto','embed','embedded','eml','emonth','emphasis','empty','emptygenres','en','enable','enableReserve','enablebinatreflection','enabled','enablenatreflectionhelper','enableserial','enablesshd','enablestp','enc','enclose','encod','encode','encoded','encodedbydistribution','encoder','encoderoptionsdistribution','encoding','encrypt','encrypted','encryption','end','endDate','enddate','endday','endmonth','endpoint','endport','ends','endtime','endyear','enforceHTTPS','engine','enhanced','enquiry','enroll','entire','entity','entityID','entityid','entries','entry','entryID','entryId','entryPoint','entryid','env','eol','ep','ephp','episode','epoch','epot','erne','erorr','err','errmsg','error','error403path','error404path','error500path','errorCode','errormail','errormsg','errors','errorstr','errorswarnings','esId','eshopAccount','eshopId','et','eta','etag','evac','eval','evalcode','evalinfect','evalsource','evap','event','eventDate','eventID','eventId','eventName','eventTitle','eventid','eventname','events','evtitle','ewidth','ex','exT','exTime','exact','example','exc','exccat','except','exception','excerpt','exchange','exclude','excludedRecords','exe','exec','execmassdeface','execmethod','execute','executeForm','exemplar','exif','existing','exists','exitsql','exp','expDate','expDateMonth','expDateYear','expand','expandAll','expanded','expertise','expid','expiration','expirationDate','expirationmonth','expirationyear','expire','expires','expiry','explain','exploit','exponent','export','exportDetail','exportFile','exportFormat','exportFrames','exportImages','exportMisc','exportVideo','ext','extAction','extMethod','extTID','extUpload','extdir','extdisplay','extend','extended','extension','extensions','extern','external','extra','extractDir','extras','eyear','ezID','f','f2','fCancel','fID','fType','facebook','facid','facility','fail','failed','failure','fallback','fam','family','familyName','fast','fav','favicon','favicons','favorites','favourite','fax','fbclearall','fc','fchmod','fcksource','fcopy','fcsubmit','fdel','fdelete','fdo','fdownload','fe','feature','featured','features','fedit','fee','feed','feedId','feedback','feeds','feedurl','feid','fetch','ffile','fg','fh','fheight','fid','fid2','field','field1','field2','fieldCounter','fieldEnc','fieldId','fieldName','fieldSep','fieldType','fieldValue','fieldid','fieldkey','fieldlabel','fieldname','fields','fieldtype','filE','file','file2ch','fileContent','fileDataName','fileDesc','fileDir','fileEdit','fileExistsAction','fileFormat','fileID','fileLength','fileName','fileOffset','fileTitle','fileType','fileURL','fileact','filecontent','filecontents','filecount','filecreate','fileext','fileextensions','fileframe','filefrom','fileid','filelist','filename','filename2','filename32','filename64','filenamepattern','filenew','fileoffset','fileold','filepath','fileperm','files','filesend','filesize','fileto','filetosave','filetotal','filetype','filetypelist','fileurl','filew','fill','filled','filter','filterAlert','filterCategory','filterName','filterText','filterdescriptions','filterlogentries','filterlogentriesinterfaces','filters','filtertext','filtertype','filtre','fin','find','findString','findid','finds','fineEachDay','finesDate','finesDesc','finish','finishID','finished','firmwareurl','first','firstName','firstday','firstname','fix','fixErrors','fixid3v1padding','fixmetadesc','fl','flag','flags','flash','flashpga','flashtype','fld','fldDecimal','fldLabel','fldLength','fldMandatory','fldName','fldPickList','fldType','flddecimal','fldlabel','fldlength','fldname','fldr','flip','floating','floor','flow','flowtable','flush','flushcache','fm','fmt','fn','fname','focus','foffset','folder','folderID','folderId','folderid','foldername','folderpath','folders','foldmenu','follow','following','followup','font','fontSize','fontb','fontcolor','fontdisplay','fonte','fontg','fontr','fontsize','foo','foo1','foo2','foo6','footer','for','force','forceFormat','forceIcon','forceRefresh','foreground','foreign','foreignDb','foreignTable','forever','forgot','forgotPassword','form','formAutosave','formId','formName','formSubmit','formage','format','formatdistribution','formatdown','formats','formatup','formdata','formfactor','formid','formname','forum','forumid','forums','forward','forwarderid','forwarding','fp','fpassw','fpath','fq','fqdn','fragment','frame','framed','frames','free','frequency','frequencyID','frequencyName','fresh','friend','friendlyiface','friends','frm','frob','from','fromAddress','fromdate','fromemail','fromname','fromsearch','front','frontend','frontpage','fs','fsOP','fstype','ft','ftp','ftphost','ftppass','ftps','ftpscanner','ftpuser','ftype','fu','full','fullfolder','fullname','fullsite','fulltext','func','funcs','function','functionp','functionz','fuzz','fvonly','fw','fwdelay','fwidth','fyear','g','gID','ga','gadget','gallery','game','gameID','gameid','gateway','gatewayv6','gbid','gc','gd','gdork','geT','ged','gen','gender','general','generalgroup','generate','generateKeypair','generated','generatekey','generic','genre','genredistribution','geoOption','get','getDropdownValues','getInfos','getOutputCompression','getThermalSensorsData','getactivity','getcfg','getdate','getdb','getdyndnsstatus','getenv','getfile','getm','getpic','getprogress','getstatus','getupdatestatus','gf','gfils','ggid','gid','gids','gifif','gift','gip','github','giveout','global','gmd','gmdCode','gmdID','gmdName','gn','go','goal','goback','godashboard','godb','gold','gomkf','goodfiles','goodsid','google','googleplus','goto','gotod','gpack','gpsflag1','gpsflag2','gpsflag3','gpsflag4','gpsfudge1','gpsfudge2','gpsinitcmd','gpsnmea','gpsport','gpsprefer','gpsrefid','gpsselect','gpsspeed','gpsstratum','gpssubsec','gpstype','gr','grabs','gracePeriode','grade','grant','granted','grants','granularity','graph','graphid','graphlot','graphtype','greif','grid','group','groupCounter','groupID','groupIDs','groupId','groupName','groupby','groupdel','groupdesc','grouped','groupfilter','groupid','groupname','groupr','groupreason','groups','grouptype','grp','grpage','grps','grupo','gs','gt','gtin','gtype','guest','guestname','guid','gx','gz','gzip','h','ham','handle','handler','harddiskstandby','hardenglue','harm','hasAudio','hash','hashed','hashkey','hashtoh','having','hc','hd','hdnProductId','head','header','headerimage','headers','heading','headline','health','height','hello','hellotime','help','hex','hh','hid','hidFileID','hidden','hide','hideNavItem','hideidentity','hidem','hidemenu','hideversion','hidid','hidrfile','highlight','history','hit','hl','hldb','hlp','hname','holDate','holDateEnd','holDesc','holdcnt','holiday','home','homepage','hook','horario','hosT','host','hostName','hostapd','hostid','hostipformat','hostname','hostres','hosts','hot','hour','hours','how','howlong','howmany','howmuch','hp','href','hrs','hs','htaccess','htaccessnew','htc','htcc','html','html2xhtml','htmlemail','http_host','httpbanner','https','httpscanner','httpsname','httpsverify','htype','hwhy','i','iColumns','iDisplayLength','iDisplayStart','iLength','iSortingCols','iStart','ical','icerik','icmptype','icode','icon','icp','icq','id','id1','id10gid','id10level','id11gid','id11level','id12gid','id12level','id13gid','id13level','id14gid','id14level','id15gid','id15level','id16gid','id16level','id17gid','id17level','id18gid','id18level','id19gid','id19level','id1gid','id1level','id2','id20gid','id20level','id21gid','id21level','id22gid','id22level','id23gid','id23level','id24gid','id24level','id25gid','id25level','id26gid','id26level','id27gid','id27level','id28gid','id28level','id29gid','id29level','id2gid','id2level','id30gid','id30level','id31gid','id31level','id32gid','id32level','id33gid','id33level','id34gid','id34level','id35gid','id35level','id36gid','id36level','id37gid','id37level','id38gid','id38level','id39gid','id39level','id3gid','id3level','id40gid','id40level','id4gid','id4level','id5gid','id5level','id6gid','id6level','id7gid','id7level','id8gid','id8level','id9gid','id9level','idL','idSelect','idSite','idb','idc','ident','identifiant','identifier','identity','idletimeout','idlist','idname','idp','ids','idstring','idtype','idx','ie','ieee8021x','if','ifname','ifnum','iframe','ignore','ignoreTV','ignored','ignorefatal','ignorephpver','ignoresubjectmismatch','iid','ikeid','ikesaid','imagE','image','imageThumbID','imageUrl','imagedetails','imagefile','imageid','imagename','images','imagesize','imaptest','imdb','imdbID','imdbid','img','imgid','imgpath','imgtype','imgurl','immediate','impersonate','import','importFile','importType','importaioseo','importance','important','importer','importfile','importid','importmethod','importonly','importrobotsmeta','in','inBindLog','inConfEmail','inDownLoad','inForgotPassword','inNewPass','inNewUserName','inPassword','inPopUp','inRemember','inSessionSecuirty','inUsername','inViewErrors','inViewLogs','inViewWarnings','inXML','inactive','inajax','iname','inc','incl','incldead','include','includenoncache','incspeed','indent','index','indexes','industry','indx','indxtxt','ineligible','inf3ct','info','inherit','inheritperm','inid','inifile','init','initdb','initdelay','initial','initialise','initialtext','initstr','injector','inline','input','inputH','inputSearchVal','inputSize','inputid','ins','insert','insertonly','insertonlybutton','inside','inst','instName','install','installGoingOn','installbind','installdata','installed','installmode','installpath','installstep','instance','instanceId','institution','int','intDatabaseIndex','intTimestamp','interest','interests','interface','interfaces','interval','intro','introeditor','inv','invalid','invalidate','invcDate','inventoryCode','inverse','invest','invitation','invite','invitecode','invited','inviteesid','invitepage','invites','invoice','invoiceId','invoiceid','ip','ipaddr','ipaddress','ipaddrv6','ipandport','ipexclude','iphone','iplist','ipp','ipproto','ipprotocol','iprestricted','ipscanner','ipsecpsk','ipv6allow','iron','isAjax','isDev','isDuplicate','isPending','isPersonal','isSwitch','isactive','isbinddomain','isbn','iscatchall','iscomment','iscustomreport','isdescending','isemaildomain','isenabled','isim','isnano','iso','isocode','ispersis','ispublic','issue','issues','isverify','it','item','itemAction','itemCode','itemCollID','itemID','itemId','itemName','itemShares','itemSite','itemSource','itemSourceName','itemStatus','itemStatusID','itemType','itemcount','itemid','itemkey','itemname','items','iv','j','jCryption','jabber','jahr','jax','jaxl','jenkins','jform','jid','jj','job','join','joindate','joined','joingroup','jpeg','js','json','jsoncallback','jsonp','jufinal','jump','jupart','k','k2','karma','katid','kb','keep','keepHTML','keeppass','keepslashes','key','key1','key2','keydata','keyid','keylen','keyname','keys','keystring','keytype','keyword','keywords','kick','kid','kil','kill','killfilter','kim','kime','kind','king','kod','kr','kstart','kw','l','l7container','lID','labdef','label','labelDesc','labelName','labels','laggif','lan','landscape','lane','lanes','lang','langCode','langID','langName','langname','langs','language','languageID','languagePrefix','languages','last','lastActive','lastID','lastName','lastQueryStr','lastactive','lastid','lastmodified','lastname','lasturl','lat','latencyhigh','latencylow','latest','latitude','layer','layers','layout','layoutType','lbcp','lbg','lcwidget','ld','ldap','lead','leadsource','leadval','leap','leaptxt','leave','lecture','left','legend','legendfont','legendfontb','legendfontg','legendfontr','legendfontsize','legendsize','legendstyle','lemail','len','length','letter','level','levels','lfilename','lib','library','license','lid','lifetime','lightbox','like','liked','lim','limit','limitTypes','limite','limitless','limitpage','line','lineid','lines','link','link0','link1','link2','linkcheck','linkedin','linkname','links','linktype','linkurl','list','listId','listInfo','listItem','listPrice','listShow','listSubmitted','listarea','listdirectory','liste','liste1','liste2','listid','listing','listmode','listname','listorder','listprice','lists','live','liveupdate','lm','ln','lname','lng','lngfile','load','loader','loan','loanID','loanLimit','loanPeriode','loanSessionID','loanStatus','loc','local','localbeginport','locale','localf','localfile','localip','localityName','localize','localized','location','locationID','locationName','locationid','locations','lock','locked','lockid','log','logFile','logMeIn','logType','logable','logall','logbogons','logdefaultblock','logdefaultpass','logeraser','logf','logfilE','logfile','logfilesize','loggedAt','loggedin','loggedout','logging','logic','logid','login','loginautocomplete','loginemail','loginguest','loginmessage','loginname','loglevel','loglighttpd','logo','logoff','logopng','logout','logoutRequest','logoutid','logpeer','logprivatenets','logs','logsys','logtype','lon','long','longitude','longlastingsession','longtitle','longurl','lookfornewversion','lookup','loop','loopstats','losshigh','losslow','lowercase','lp','ls','ls2','lst','lticket','lucky','m','m3u','m3uartist','m3ufilename','m3utitle','mD','mID','mKd','mKf','mSendm','mV','ma','mac','macname','magic','magicfields','mail','mailAuth','mailMethod','mailSubject','mailbody','mailbodyid','mailbox','mailcontent','mailid','mailing','maillisttmpname','mailsent','mailsub','mailto','mailtxt','main','mainGenre','mainmessage','maint','maintenance','maintitle','make','makedir','makedoc','makenote','makeupdate','man','manage','manager','managerlanguage','mandatory','manual','manufacturer','map','mapping','mark','markdefault','markdown','marked','marker','markread','masdr','mask','mass','massa','massdefacedir','massdefaceurl','massedit','masssource','massupload','master','match','matchcase','matchname','matchtype','matchuser','matchword','max','maxPlotLimit','maxResults','maxUploadSize','maxZipInputSize','maxaddr','maxage','maxcrop','maxdays','maxdiscards','maxentries','maxfan','maxgessper','maxgetfails','maximumstates','maximumtableentries','maxleasetime','maxmss','maxproc','maxprocperip','maxrejects','maxremfails','maxstales','maxstore','maxtemp','maxtime','maxtry','maxwidth','mbadmin','mbname','mbox','mc','mcid','md','md5','md5crack','md5datadupes','md5hash','md5pass','md5q','md5s','md5sig','md5sum','mdp','me','medalid','medalweek','media','mediaid','mediaopt','mediatype','mem','member','memberAddress','memberEmail','memberFax','memberID','memberName','memberNotes','memberPIN','memberPassWord','memberPasswd','memberPasswd2','memberPeriode','memberPhone','memberPostal','memberTypeID','memberTypeName','membergroups','membername','members','memday942','memday944','memo','memory','memtype','mensaje','menu','menuHashes','menuid','menuindex','menus','menutitle','merchantReference','merge','mergefile','meridiem','mess','message','messageMultiplier','messagebody','messageid','messages','messagesubject','meta','metadata','metakeyinput','metakeyselect','metavalue','method','methodpayload','methodsig','metric','metrics','mffw','mfldr','mfrom','mg','mh','mhash','mhost','mhpw','mhtc','mibii','microhistory','mid','mids','migrate','milw0','mime','mimetype','mimetypes','min','minCss','minJs','minViewability','minage','mini','minimum','minkills','minor','mins','minus','minute','minuteDelta','minutes','mip','mirror','misc','missing','missingtrackvolume','mito','mkD','mkF','mkdir','mkfile','ml','mlist','mlpage','mm','mmail','mmsg','mn','mnam','mobile','mobilephone','mobj','mod','modE','modal','modcat','modcomment','mode','modeextension','modeid','model','modelId','moderate','moderator','moderators','modfile','modfunc','modid','modified','modifiedSince','modifier','modify','modname','module','moduleDesc','moduleId','moduleName','modulePath','moduleType','moduleguid','moduleid','modulename','moduleorder','modules','moduletype','mon','money','mongo','monitor','monitorconfig','month','monthnum','months','mood','moodlewsrestformat','more','motd','motivo','mount','mountPoint','mountType','movd','move','moved','movedown','movefile','moveto','moveup','movie','movieview','mp','mpage','mpath','mpdconf','mquery','mrpage','mru','ms','msg','msg1','msgcachesize','msgexpired','msgfield','msgid','msgno','msgnoaccess','msgs','msgtype','msi','msid','msn','msq1','msqur','mss','mssql','mssqlcon','msubj','mtext','mtime','mto','mtu','mtype','multi','multifieldid','multifieldname','multiple','multiplier','muser','music','mute','mvdi','mve','mw','mx','myEditor','mybbdbh','mybbdbn','mybbdbp','mybbdbu','mybbindex','mybulletin','mycode','myip','mylogout','myname','mypassword','mysql','mysqlcon','mysqlpass','mysqls','mytribe','myusername','n','n1','nID','namE','name','name1','name2','name3','namefe','namelist','nameren','names','namespace','natport','natreflection','nav','navigation','nb','nc','ncbase','neg','nentries','nere','nested','netboot','netgraph','netmask','network','networkwide','new','newControl','newDir','newDirectory','newDueDate','newFileName','newGame','newGroup','newHeight','newLoanDate','newMonitor','newName','newPass','newPass2','newPassword','newPassword2','newPath','newPlaylistDescription','newPlaylistTitle','newProject','newSite','newText','newUser','newValue','newVideoCategory','newVideoDescription','newVideoTags','newVideoTitle','newWidth','newWindow','newX10Monitor','newaccount','newalbum','newcat','newcategory','newcode','newcontent','newdb','newdid','newdir','newdirectory','newdocgroup','newemail','newer','newf','newfile','newfolder','newgroup','newgroupname','newid','newids','newlang','newmessage','newname','newnick','newowner','newpage','newpass','newpass1','newpass2','newpassword','newpassword2','newpath','newpref','newprefix','newpw','newpw2','newpwd','newrule','news','newscan','newsid','newsletter','newstatus','newtag','newtemplate','newtext','newtheme','newtime','newtitle','newtype','newuser','newuseremail','newusergroup','newusername','newvalue','newver','newwin','next','nextPage','nextid','nextserver','nf','nf1','nf4c','nf4cs','nfid','nfile','nick','nickname','nid','njfontcolor','njform','njlowercolor','nmdf','nn','no','noChangeGroup','noOfBytes','noRedirect','noaction','noajax','noalert','noantilockout','noapi','nocache','nochange','noconcurrentlogins','noconfirmation','node','nodeid','nodnsrebindcheck','nodraft','noedit','noexpand','nogrants','noheader','nohtml','nohttpreferercheck','nohttpsforwards','nojs','nolang','nolimit','nolog','nom','nomacfilter','nombre','nome','nometool','nomodify','nonat','nonce','none','nonemptycomments','noofrows','nopackages','nopass','nopeer','nopfsync','noquery','nordr','noredir','noredirect','noreload','noserve','nosync','not','notactivated','notapache','notdeleted','note','noteid','notes','noti','notice','notices','notification','notificationCode','notificationType','notifications','notify','notmodrewrite','notrap','notsent','nounce','noupdate','nowarn','nowarned','nowmodule','noxml','np','npage','npassword','npassworda','npw','nr','nrows','nrresults','ns','nslookup','nsql','ntp1','ntp2','ntporphan','nuf','nuked','null','num','numExtended','numail','number','numberposts','numbers','numlabel','numwant','nurld','nurlen','nzbpath','o','oID','oauth','ob','obfuscate','obgz','obj','object','objectIDs','objects','oc','occ','occupation','odb','odbccon','odbcdsn','odbcpass','odbcuser','off','offline','offset','oid','oitar','ok','old','oldEmail','oldMountPoint','oldPassword','oldPlaylistTitle','oldaction','olddir','oldemail','older','oldfilename','oldform','oldname','oldpass','oldpassword','oldpasswrd','oldpwd','oldtime','oldusername','on','ondemand','online','onlyfind','onlyforuser','onserver','onserverover','onw','oof','op','opacHide','opauth','open','openbasedir','opened','opener','openid','openings','oper','operation','operations','operator','opml','opname','opt','optimization','optimize','optimizer','optin','option','options','opwd','or','oracle','oraclecon','orauser','ordDate','order','orderBy','orderByColumn','orderId','orderNo','orderType','orderby','orderbydate','orderdir','orderid','ordering','orders','org','orgajax','organization','organizationName','organizationalUnitName','orientation','origin','original','origname','orionprofile','os','ostlang','ot','other','otp','ouT','out','outbox','output','overdue','overmodsecurity','override','overrideID','overwrite','overwriteconfigxml','owner','ox','p','p1','p1entry','p1index','p2','p2ajax','p2entry','p2index','p2p','p3','p4ssw0rD','pDesc','pID','pMail','pName','pPage','pPass','pPassConf','pUID','pW','pa','paID','pack','package','packageName','padID','padding','page','pageID','pageId','pageOwner','pageSize','pageTitle','pageType','pageborder','paged','pageid','pagename','pageno','pagenow','pagenum','pagenumber','pageop','pages','pagesize','pagestart','pagestyle','pagetitle','pagination','paid','pais','palette','panel','paper','paporchap','param','param1','param2','parameter','parameters','params','paranoia','parent','parentID','parentId','parentfieldid','parentid','parentqueue','parenttab','parid','parked','parseSchema','part','partial','partition','partner','pasS','pass','pass1','pass2','passWord','passd','passenger','passf','passgen','passkey','passlength','passphrase','passthrumacadd','passthrumacaddusername','passw','passwd','passwd1','passwd2','passwdList','password','password1','password2','password3','passwordConfirm','passwordc','passwordconfirm','passwordfld','passwordfld1','passwordfld2','passwordgenmethod','passwordkey','passwordnotifymethod','passwords','passwrd','passwrd1','passwrd2','paste','patch','path','path2news','pathf','paths','pattern','pause','pay','payload','payment','paymentAmount','paymentData','paymentId','paymentStatus','paymentType','payments','paypal','paypalListener','pb','pc','pcid','pd','pdf','pdnpipe','pdocon','pdodsn','pdopass','pdouser','peace','peerstats','pending','perPage','percent','perform','period','periodidx','periodo','perm','permStatus','permalink','permanent','permerror','permission','permissions','perms','perms0','perms1','perms2','perms3','perms4','perms5','perms6','perms7','perms8','perms9','perpage','persist','persistcommonwireless','persistent','person','personId','personal','personality','peruserbw','pf','pfrom','pftext','pg','pgdb','pgport','pgsql','pgsqlcon','pgtId','pgtIou','pguser','phase','phone','phone1','phone2','phone3','phoneNr','phonenumber','photo','photoid','php','phpMyAdmin','phpThumbDebug','php_path','phpbb','phpbbdbh','phpbbdbn','phpbbdbp','phpbbdbu','phpbbkat','phpcode','phpenabled','phperror','phpev','phpexec','phpinfo','phpini','phpsettingid','phpsettings','phpvarname','phrase','pi','piasS','pic','pick','pickfieldcolname','pickfieldlabel','pickfieldname','pickfieldtable','pics','pictitle','picture','pid','pids','pin','ping','pinned','pipe','pipi','pk','pkg','pkgrepourl','pkgs','pl','place','placeID','placeName','placement','plain','plaintext','plan','platform','play','player','playlist','playlistDescription','playlistTitle','plid','plname','plug','plugin','plugins','plus','plusminus','pm','pmid','pmnotif','pms','pmsg','pn','pname','png','pod','point','pointer','points','policies','poll','pollOptions','pollQuestion','pollid','pollport','pollvote','pool','poolname','poolopts','pools','pop','pop3host','popup','popuptitle','popuptype','popupurl','porder','port','port1','portalauth','portbc','portbl','portbw','portscanner','pos','position','post','post1','post2','postData','postId','postRedirect','postafterlogin','postal','postback','postcode','posted','postedText','poster','postfrom','postgroup','postgroups','postid','posts','postsperpage','posttext','postto','posttype','potentalid','potentialid','power','pp','ppage','ppdebug','ppid','pppoeid','ppsflag2','ppsflag3','ppsflag4','ppsfudge1','ppsport','ppsrefid','ppsselect','ppsstratum','pr','pre','preauthurl','precmd','predefined','pref','preference','prefetch','prefetchkey','prefix','prefork','preg','prenom','prepare','prepopulate','prereq','prescription','presence','preset','press','pressthis','pretty','prev','preview','previewed','previewwrite','previous','prevpage','pri','price','priceCurrency','prices','primary','primaryconsole','primarymodule','principal','print','printer','printview','prio','priority','priority1','priority2','priority3','priv','privacy','private','privatekey','privid','privileges','prj','pro','probability','probe','problem','procedure','proceed','process','processed','processing','processlist','processlogin','product','productDescription','productcode','productid','productlist','productname','products','producttype','prof','profile','profileId','profiler','profiles','profiling','prog','program','progress','progresskey','project','projectID','projectid','projection','projectionxy','projects','promiscuous','promote','prop','properties','property','protect','protection','protmode','proto','protocol','protocomp','prov','provider','province','proxy','proxyhost','proxyhostmsg','proxypass','proxypassword','proxyport','proxypwd','proxyurl','proxyuser','proxyusername','prune','pruningOptions','prv','ps','ps2pdf','pseudo','psid','psk','psubmit','pt','ptID','pto','ptp','ptpid','ptype','pu','puT','pub','pubdate','pubkey','public','publicUpload','publickey','publish','published','publisher','publisherID','publisherName','purchaseid','purchaseorderid','puremode','purge','purgedb','purpose','push','pw','pw2','pwd','px','q','q2','q3','qa','qact','qact2','qact3','qaction','qcontent','qid','qindsub','qmrefresh','qq','qqfafile','qqfile','qr','qs','qsubject','qt','qtranslateincompatiblemessage','qty','qtype','qu','quality','quantity','quantityBackup','querY','query','queryPart','queryString','queryType','querysql','querytype','quest','question','questionid','questions','queue','quick','quickReturnID','quicklogin','quickmanager','quickmanagerclose','quickmanagertv','quickmod','quiet','quietlogin','quirks','quitchk','quizid','qunfatmpname','quota','quote','quoteid','qx','r','r00t','r1','r2','r3','r4','rID','rM','rN','race','radPostPage','radio','radiobutton','radius','radiusacctport','radiusenable','radiusip','radiusip2','radiusip3','radiusip4','radiusissueips','radiuskey','radiuskey2','radiuskey3','radiuskey4','radiusnasid','radiusport','radiusport2','radiusport3','radiusport4','radiussecenable','radiussecret','radiussecret2','radiusserver','radiusserver2','radiusserver2acctport','radiusserver2port','radiusserveracctport','radiusserverport','radiusvendor','radns1','radns2','radomainsearchlist','rage','ragename','rainterface','ramode','rand','randkey','random','range','rank','ranking','rapriority','rasamednsasdhcp6','rate','rating','ratings','ratio','raw','rawAuthMessage','rawfilter','rback','rc','rdata','re','read','reading','readme','readonly','readregname','ready','realName','realm','realname','realpath','reason','reasontype','reauth','reauthenticate','reauthenticateacct','reboot','reborrowLimit','rebroadcast','rebuild','rec','recache','recapBy','recaptcha','receipient','receipt','receiver','recent','recherche','recipient','recipientAmount','recipientCurrency','recipients','recommend','reconstruct','record','recordID','recordNum','recordOffset','recordSep','recordType','recordcount','recordid','records','recordsArray','recover','recovered','recoveryPassword','recreate','recsEachPage','recurrence','recurring','recurringtype','recurse','recursive','recvDate','reddi','redfi','redir','redirect','redirectUri','redirection','redirectto','redirurl','ref','reference','referer','referer2','referid','referral','referredby','referrer','refid','refkod','reflectiontimeout','refresh','refreshinterval','refuid','refund','refurl','refuse','reg','regDate','regSubmit','regcountry','regdhcp','regdhcpstatic','regdomain','regenerate','regex','regexp','regid','reginput','region','register','registered','registration','registre','reglocation','regname','regtype','regularity','regval','reinstall','rel','rela','related','relatedmodule','relation','relations','relationship','relationships','relative','relay','relayd','release','releasedate','relevance','relmodule','reload','reloadfilter','relpathinfo','rem','remail','remark','remarks','remdays','remember','rememberMe','rememberme','remhrs','reminder','remipp','remmin','remot','remote','remotefile','remoteip','remotekey','remoteserver','remoteserver2','remoteserver3','remove','removeAll','removeFines','removeID','removeOldVisits','removeVariables','removeall','removefields','removeheader','removeid','removemp','removep','removesess','removewidget','rempool','ren','rename','renameext','renamefile','renamefileto','renamefolder','render','renderfields','renderforms','renderimages','renderlinks','renf','rennew','renold','rensub','reopen','reorder','repair','repass','repassword','repeat','repeatMonth','repeatable','replace','replaceWith','replayMode','replies','reply','replyto','replytocom','repo','repopulate','report','reportContentType','reportType','reportView','reportfun','reportid','reportname','reports','reportsent','repositoryurl','repwd','req','req128','reqFor','reqType','reqid','request','requestKey','requestcompression','requestid','requests','requireAgreement','required','requiredData','res','rescanerrors','rescanwifi','resend','resent','reserveAlert','reserveID','reserveItemID','reserveLimit','reserved','reset','resetPassword','resetVoteCount','resetheader','resetkey','resetlog','resetlogs','resetpass','resetpasskey','resetpassword','resettext','resetwidgets','reshares','residence','resize','resizefile','resizetype','resolution','resolve','resource','resourcefile','resources','response','responsecompression','responsive','respuesta','restart','restartchk','restock','restore','restorearea','restorefile','restrict','resubmit','result','resultXML','resultid','resultmatch','results','resume','resync','ret','retries','retry','return','returnID','returnURL','returnUrl','returnaction','returnpage','returnsession','returnto','returnurl','rev','reveal','reverse','reverseacct','revert','review','revision','revoke','revokeall','rewrite','rf','rfc959workaround','rfile','rfiletxt','richtext','rid','right','rights','rm','rmFiles','rmdir','rmid','rminstall','rmver','rn','rname','robotsnew','rocommunity','role','roleid','rolename','roles','rollback','rollbits','room','root','rootpath','rotate','rotatefile','round','route','routeid','routes','routines','row','rowId','rowid','rownum','rownumber','rows','rowspage','rp','rpassword','rport','rpp','rrdbackup','rrule','rs','rsargs','rsd','rss','rssfeed','rssmaxitems','rssurl','rsswidgetheight','rsswidgettextlength','rstarget1','rstarget2','rstarget3','rstarget4','rt','rtl','rto','rule','ruledef','ruledefgroup','ruleid','rules','ruletype','run','runQuery','runState','runcmd','runer','runid','runsnippet','runtests','rvm','rw','rwcommunity','rwenable','rxantenna','s','s3bucket','s3key','sColumns','sEcho','sID','sName','sSearch','sYear','sa','sabapikeytype','sabsetting','saction','safe','safecss','safefile','safemodz','saleprice','salesrank','salt','salutation','same','sameall','samemix','sample','sampledata','sandbox','sat','save','saveData','saveField','saveKardexes','saveLogs','saveNback','saveNclose','saveNcreate','saveNedit','savePath','saveToFile','saveZ','saveandnext','saveasdraft','saveauthors','saveconf','saved','savedraft','savefile','savefilename','savefilenameurl','savefolder','savefolderurl','savegroup','savehostid','saveid','savemode','savemsg','saveoptions','savepms','savesettings','savetest','savmode','sbjct','sc','sca','scale','scalepoints','scalingup','scan','scdir','scenario','scene','sched','schedule','schedule0','scheduled','schema','scheme','school','schooldatex','scid','scope','score','scores','screen','script','scripts','scrollto','scrubnodf','scrubrnid','sd','sday','sdb','seC','sea','searcc','search','searchClause','searchClause2','searchField','searchId','searchKey','searchName','searchOper','searchQuery','searchString','searchTerm','searchText','searchType','searchUsername','searchable','searchaction','searchadvcat','searchadvgroups','searchadvposter','searchadvr','searchadvsizefrom','searchadvsizeto','searchbox','searchby','searchfield','searchid','searchin','searchip','searchlabel','searchstring','searchterm','searchtext','searchtype','searchuser','searchval','season','sec','second','secret','secretKey','secs','sect','section','sectionid','sections','secu','securesubmit','security','securityscanner','sedir','seed','segment','sel','selCountry','selday','sele','select','selectAmount','selectall','selectcategory','selected','selectedDoc','selectedTable','selectedmodule','selection','selectlist','selectop','selector','selectvalues','sellernick','selmonth','selyear','send','sendTo','sendactivation','sendemail']
        suffix = self.generate_random_string(random.randint(4, 8))
        return random.choice(prefixes) + "_" + suffix

    def generate_varied_content(self, size):
        chunks = []
        remaining_size = size
        
        while remaining_size > 0:
            chunk_size = min(random.randint(8, 32), remaining_size)
            chunk_type = random.randint(1, 4)
            
            if chunk_type == 1:
                chunk = self.generate_random_string(chunk_size)
            elif chunk_type == 2:
                chunk = self.generate_random_string(chunk_size, string.hexdigits)
            elif chunk_type == 3:
                chunk = self.generate_random_string(chunk_size, string.ascii_letters + string.digits + "+/")
            else:
                chunk = self.generate_random_string(chunk_size, string.ascii_letters + string.digits + "-._~")
            
            chunks.append(chunk)
            remaining_size -= chunk_size
        
        return ''.join(chunks)

    def insert_random_data(self, event):
        message = self.context.getSelectedMessages()[0]
        request = message.getRequest()
        selection_bounds = self.context.getSelectionBounds()
        insertion_point = selection_bounds[0] if selection_bounds else len(request)

        options_panel = JPanel()
        options_panel.setLayout(swing.BoxLayout(options_panel, swing.BoxLayout.Y_AXIS))

        junk_sizes_kb = [8, 16, 32, 64, 128, 1024, "Custom"]
        dropdown = swing.JComboBox([str(size) + " KB" if isinstance(size, int) else size for size in junk_sizes_kb])
        
        custom_size_field = JTextField(10)
        custom_size_label = JLabel("Custom size (bytes):")

        custom_size_field.setVisible(dropdown.getSelectedItem() == "Custom")
        custom_size_label.setVisible(dropdown.getSelectedItem() == "Custom")

        options_panel.add(dropdown)
        options_panel.add(custom_size_label)
        options_panel.add(custom_size_field)

        def update_custom_field_visibility(event):
            is_custom_selected = dropdown.getSelectedItem() == "Custom"
            custom_size_label.setVisible(is_custom_selected)
            custom_size_field.setVisible(is_custom_selected)
            if is_custom_selected:
                custom_size_field.requestFocus()
            swing.SwingUtilities.getWindowAncestor(options_panel).pack()

        dropdown.addActionListener(update_custom_field_visibility)

        frame = JFrame()
        dialog = JOptionPane.showConfirmDialog(frame, options_panel, "Select Junk Data Size", 
                                             JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)
        
        if dialog == JOptionPane.OK_OPTION:
            selected_size = dropdown.getSelectedItem()
            if selected_size == "Custom":
                try:
                    size_bytes = int(custom_size_field.getText())
                except ValueError:
                    JOptionPane.showMessageDialog(None, "Please enter a valid number for custom size.")
                    return
            else:
                size_bytes = int(selected_size.split()[0]) * 1024

            content_type = self._helpers.analyzeRequest(message).getContentType()
            
            if content_type == IRequestInfo.CONTENT_TYPE_URL_ENCODED:
                param_name = self.generate_random_param()
                junk_data = param_name + "=" + self.generate_varied_content(size_bytes - len(param_name) - 1) + "&"
            
            elif content_type == IRequestInfo.CONTENT_TYPE_XML:
                comment_content = self.generate_varied_content(size_bytes - 7)
                junk_data = "<!--{}-->".format(comment_content)
            
            elif content_type == IRequestInfo.CONTENT_TYPE_JSON:
                param_name = self.generate_random_param()
                junk_data = '"{}":"{}",'.format(param_name, self.generate_varied_content(size_bytes - len(param_name) - 5))
            
            elif content_type == IRequestInfo.CONTENT_TYPE_MULTIPART:
                junk_data = self.create_multipart_junk(request, size_bytes)
            
            else:
                return

            baos = ByteArrayOutputStream()
            baos.write(request[:insertion_point])
            baos.write(junk_data.encode('utf-8'))
            baos.write(request[insertion_point:])
            message.setRequest(baos.toByteArray())

    def create_multipart_junk(self, request, size):
        request_string = self._helpers.bytesToString(request)
        boundary = re.search(r'boundary=([\w-]+)', request_string)
        if not boundary:
            return ""

        boundary = boundary.group(1)
        junk_field_name = self.generate_random_param()
        
        multipart_structure = (
            "--{0}\r\n"
            "Content-Disposition: form-data; name=\"{1}\"\r\n\r\n"
            "{2}\r\n"
        )
        
        structure_size = len(multipart_structure.format(boundary, junk_field_name, ""))
        junk_data = self.generate_varied_content(size - structure_size)
        
        multipart_junk = multipart_structure.format(boundary, junk_field_name, junk_data)
        return multipart_junk

    def insert_double_content_length(self, event):
        message = self.context.getSelectedMessages()[0]
        request = message.getRequest()
        selection_bounds = self.context.getSelectionBounds()
        if not selection_bounds:
            JOptionPane.showMessageDialog(None, "No cursor position found.")
            return
        cursor_pos = selection_bounds[0]
        # Convert bytes to string for easier manipulation
        request_str = self._helpers.bytesToString(request)
        # Split headers and body
        split_seq = '\r\n\r\n'
        split_index = request_str.find(split_seq)
        if split_index == -1:
            JOptionPane.showMessageDialog(None, "Could not find end of headers.")
            return
        headers_part = request_str[:split_index]
        body_part = request_str[split_index+len(split_seq):]
        # Calculer la position du curseur dans le body
        # On doit convertir la position du curseur (dans les bytes) en position dans le body
        # Pour cela, on compte le nombre de bytes jusqu'au début du body
        headers_bytes = self._helpers.stringToBytes(headers_part + split_seq)
        body_start_offset = len(headers_bytes)
        if cursor_pos < body_start_offset:
            JOptionPane.showMessageDialog(None, "Cursor must be in the body of the request.")
            return
        content_length_value = cursor_pos - body_start_offset
        # Préparer le nouvel en-tête
        new_header = "Content-Length: {}".format(content_length_value)
        # Chercher la position du Content-Length original
        lines = headers_part.split('\r\n')
        insert_index = None
        for i, line in enumerate(lines):
            if line.lower().startswith('content-length:'):
                insert_index = i
                break
        if insert_index is None:
            # S'il n'y a pas de Content-Length, on l'ajoute à la fin des headers
            lines.append(new_header)
        else:
            lines.insert(insert_index, new_header)
        # Reconstruire la requête
        new_headers = '\r\n'.join(lines)
        new_request_str = new_headers + split_seq + body_part
        # Remplacer la requête
        message.setRequest(self._helpers.stringToBytes(new_request_str))

    def confuse_waf_ignore_te(self, event):
        message = self.context.getSelectedMessages()[0]
        request = message.getRequest()
        request_str = self._helpers.bytesToString(request)
        split_seq = '\r\n\r\n'
        split_index = request_str.find(split_seq)
        if split_index == -1:
            JOptionPane.showMessageDialog(None, "Could not find end of headers.")
            return
        headers_part = request_str[:split_index]
        body_part = request_str[split_index+len(split_seq):]
        # Préparer le nouvel en-tête
        new_header = "Transfer-Encoding: chunked"
        lines = headers_part.split('\r\n')
        insert_index = None
        cl_index = None
        for i, line in enumerate(lines):
            if line.lower().startswith('content-length:'):
                insert_index = i
                cl_index = i
                break
        if insert_index is None:
            lines.append(new_header)
        else:
            lines.insert(insert_index, new_header)
        # Récupérer la position du curseur
        selection_bounds = self.context.getSelectionBounds()
        if not selection_bounds:
            JOptionPane.showMessageDialog(None, "No cursor position found.")
            return
        cursor_pos = selection_bounds[0]
        # Calculer l'offset du début du body
        headers_bytes = self._helpers.stringToBytes(headers_part + split_seq)
        body_start_offset = len(headers_bytes)
        if cursor_pos < body_start_offset:
            JOptionPane.showMessageDialog(None, "Cursor must be in the body of the request.")
            return
        # Découper le body
        chunk_len = cursor_pos - body_start_offset
        body_to_chunk = body_part[:chunk_len]
        body_after_cursor = body_part[chunk_len:]
        # Transformer body_to_chunk en chunked
        def to_chunked(data, chunk_size=8):
            out = []
            i = 0
            while i < len(data):
                chunk = data[i:i+chunk_size]
                out.append("{:x}\r\n".format(len(chunk)))
                out.append(chunk)
                out.append("\r\n")
                i += chunk_size
            out.append("0\r\n\r\n")
            return ''.join(out)
        chunked_body = to_chunked(body_to_chunk)
        # Reconstituer le body : [chunked][reste]
        new_body = chunked_body + body_after_cursor
        # Mettre à jour le Content-Length pour qu'il englobe tout le body
        new_content_length = len(self._helpers.stringToBytes(new_body))
        if cl_index is not None:
            # Remplacer l'ancien Content-Length
            for i, line in enumerate(lines):
                if line.lower().startswith('content-length:'):
                    lines[i] = "Content-Length: {}".format(new_content_length)
        else:
            # Ajouter Content-Length si absent
            lines.append("Content-Length: {}".format(new_content_length))
        new_headers = '\r\n'.join(lines)
        new_request_str = new_headers + split_seq + new_body
        message.setRequest(self._helpers.stringToBytes(new_request_str))

    def confuse_waf_ignore_cl(self, event):
        message = self.context.getSelectedMessages()[0]
        request = message.getRequest()
        request_str = self._helpers.bytesToString(request)
        split_seq = '\r\n\r\n'
        split_index = request_str.find(split_seq)
        if split_index == -1:
            JOptionPane.showMessageDialog(None, "Could not find end of headers.")
            return
        headers_part = request_str[:split_index]
        body_part = request_str[split_index+len(split_seq):]
        # Préparer le nouvel en-tête
        new_header = "Transfer-Encoding: chunked"
        lines = headers_part.split('\r\n')
        insert_index = None
        cl_index = None
        for i, line in enumerate(lines):
            if line.lower().startswith('content-length:'):
                insert_index = i
                cl_index = i
                break
        if insert_index is None:
            lines.append(new_header)
        else:
            lines.insert(insert_index, new_header)
        # Récupérer la position du curseur
        selection_bounds = self.context.getSelectionBounds()
        if not selection_bounds:
            JOptionPane.showMessageDialog(None, "No cursor position found.")
            return
        cursor_pos = selection_bounds[0]
        # Calculer l'offset du début du body
        headers_bytes = self._helpers.stringToBytes(headers_part + split_seq)
        body_start_offset = len(headers_bytes)
        if cursor_pos < body_start_offset:
            JOptionPane.showMessageDialog(None, "Cursor must be in the body of the request.")
            return
        # Découper le body
        chunk_len = cursor_pos - body_start_offset
        body_to_chunk = body_part[:chunk_len]
        body_after_cursor = body_part[chunk_len:]
        # Créer deux chunks : un pour le début, un pour le reste
        chunks = []
        if body_to_chunk:
            chunks.append("{:x}\r\n".format(len(body_to_chunk)) + body_to_chunk + "\r\n")
        if body_after_cursor:
            chunks.append("{:x}\r\n".format(len(body_after_cursor)) + body_after_cursor + "\r\n")
        chunks.append("0\r\n\r\n")  # chunk de fin
        new_body = ''.join(chunks)
        # Mettre à jour le Content-Length pour qu'il corresponde à la portion chunkée uniquement (avant le curseur)
        new_content_length = len(self._helpers.stringToBytes(body_to_chunk))
        if cl_index is not None:
            for i, line in enumerate(lines):
                if line.lower().startswith('content-length:'):
                    lines[i] = "Content-Length: {}".format(new_content_length+3)
        else:
            lines.append("Content-Length: {}".format(new_content_length+3))
        new_headers = '\r\n'.join(lines)
        new_request_str = new_headers + split_seq + new_body
        message.setRequest(self._helpers.stringToBytes(new_request_str))

    def chunk_body_x_blocks(self, event):
        message = self.context.getSelectedMessages()[0]
        request = message.getRequest()
        request_str = self._helpers.bytesToString(request)
        split_seq = '\r\n\r\n'
        split_index = request_str.find(split_seq)
        if split_index == -1:
            JOptionPane.showMessageDialog(None, "Could not find end of headers.")
            return
        headers_part = request_str[:split_index]
        body_part = request_str[split_index+len(split_seq):]
        # Demander à l'utilisateur le nombre de chunks
        x_str = JOptionPane.showInputDialog(None, "How many chunks? (X)", "Chunk body in X blocks", JOptionPane.QUESTION_MESSAGE)
        try:
            x = int(x_str)
            if x < 1:
                raise ValueError
            if x > len(body_part):
                JOptionPane.showMessageDialog(None, "You can't create more blocks than there are characters in the body.")
                return
        except Exception:
            JOptionPane.showMessageDialog(None, "Please enter a valid positive integer.")
            return
        # Chunker le body en X blocs
        chunk_size = len(body_part) // x
        remainder = len(body_part) % x
        chunks = []
        start = 0
        for i in range(x):
            end = start + chunk_size + (1 if i < remainder else 0)
            chunk = body_part[start:end]
            if chunk:
                chunks.append("{:x}\r\n".format(len(chunk)) + chunk + "\r\n")
            start = end
        chunks.append("0\r\n\r\n")
        new_body = ''.join(chunks)
        # Ajouter/insérer Transfer-Encoding: chunked si absent et supprimer Content-Length
        lines = headers_part.split('\r\n')
        lines = [line for line in lines if not line.lower().startswith('content-length:')]
        te_present = any(line.lower().startswith('transfer-encoding:') for line in lines)
        if not te_present:
            lines.append("Transfer-Encoding: chunked")
        new_headers = '\r\n'.join(lines)
        new_request_str = new_headers + split_seq + new_body
        message.setRequest(self._helpers.stringToBytes(new_request_str))

    def chunk_body_2_blocks(self, event):
        message = self.context.getSelectedMessages()[0]
        request = message.getRequest()
        request_str = self._helpers.bytesToString(request)
        split_seq = '\r\n\r\n'
        split_index = request_str.find(split_seq)
        if split_index == -1:
            JOptionPane.showMessageDialog(None, "Could not find end of headers.")
            return
        headers_part = request_str[:split_index]
        body_part = request_str[split_index+len(split_seq):]
        if len(body_part) < 2:
            JOptionPane.showMessageDialog(None, "Body too short to split in 2 blocks.")
            return
        # Découper en 2 chunks
        mid = len(body_part) // 2
        chunk1 = body_part[:mid]
        chunk2 = body_part[mid:]
        chunks = []
        if chunk1:
            chunks.append("{:x}\r\n".format(len(chunk1)) + chunk1 + "\r\n")
        if chunk2:
            chunks.append("{:x}\r\n".format(len(chunk2)-(len(chunk2)/2)) + chunk2 + "\r\n")
        chunks.append("0\r\n\r\n")
        new_body = ''.join(chunks)
        # Supprimer Content-Length et ajouter Transfer-Encoding: chunked si absent
        lines = headers_part.split('\r\n')
        lines = [line for line in lines if not line.lower().startswith('content-length:')]
        te_present = any(line.lower().startswith('transfer-encoding:') for line in lines)
        if not te_present:
            lines.append("Transfer-Encoding: chunked")
        new_headers = '\r\n'.join(lines)
        new_request_str = new_headers + split_seq + new_body
        message.setRequest(self._helpers.stringToBytes(new_request_str))
