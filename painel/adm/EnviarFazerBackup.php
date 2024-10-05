<?php
	set_time_limit(0);
	include("conexao.php");
	include_once("functions.php");
	include_once(Idioma(1));
	global $_TRA;
		
	$BackupAgora = (isset($_POST['id'])) ? $_POST['id'] : '';
	
	$SqlStatusServer = "SELECT * FROM backup";
	$SqlStatusServer = $painel_geral->prepare($SqlStatusServer);
	$SqlStatusServer->execute();
	$LnStatusServer = $SqlStatusServer->fetch();
	
	$EnviarStatus = $LnStatusServer['status'];
	$tempo = $LnStatusServer['tempo'];
	$horario = $LnStatusServer['horario'];
	$email = $LnStatusServer['email'];
	
	$DataAtual = time();
	
	//Verifica se o Backup está ativado
	if($EnviarStatus != "S"){
		echo MensagemAlerta($_TRA['erro'], $_TRA['nfprobnesa'], "danger");
		exit;
	}
	
	if(empty($tempo)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['nfprobnest'], "danger");
		exit;
	}
	
	if(empty($horario)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['nfprobnesh'], "danger");
		exit;
	}
	
	if(empty($email)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['nfprobnese'], "danger");
		exit;
	}
	
	if( ($BackupAgora != "BackupAgora") ){
		if($DataAtual < $horario){
			exit;
		}
	}
	
	///////////////////////////////////////////////////////////
	///                   INICIO O BACKUP                   ///
	///////////////////////////////////////////////////////////
	
	class MySql{
        private $dbc;
        private $user;
        private $pass;
        private $dbname;
        private $host;

        function __construct($host, $dbname, $user, $pass){
            $this->user = $user;
            $this->pass = $pass;
            $this->dbname = $dbname;
            $this->host = $host;
            $opt = array(
               PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
               PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
            );
            try{
                $this->dbc = new PDO('mysql:host='.$this->host.';dbname='.$this->dbname.';charset=utf8', $user, $pass, $opt);
            }
            catch(PDOException $e){
                 echo MensagemAlerta($_TRA['erro'], $e->getMessage()."<br>".$_TRA['nfprob'], "danger");
            }
        }


        public function backup_tables($tables = '*'){
            $host=$this->host;
            $user=$this->user;
            $pass=$this->pass;
            $dbname=$this->dbname;
            $data = "";

            if($tables == '*')
            {
                $tables = array();
                $result = $this->dbc->prepare('SHOW TABLES'); 
                $result->execute();                         
                while($row = $result->fetch(PDO::FETCH_NUM)) 
                { 
                    $tables[] = $row[0]; 
                }
            }
            else
            {
                $tables = is_array($tables) ? $tables : explode(',',$tables);
            }

            foreach($tables as $table)
            {
                $resultcount = $this->dbc->prepare('SELECT count(*) FROM '.$table);
                $resultcount->execute();
                $num_fields = $resultcount->fetch(PDO::FETCH_NUM);
                $num_fields = $num_fields[0];

                $result = $this->dbc->prepare('SELECT * FROM '.$table);
                $result->execute();
                $data.= 'DROP TABLE IF EXISTS '.$table.';';

                $result2 = $this->dbc->prepare('SHOW CREATE TABLE '.$table);    
                $result2->execute();                            
                $row2 = $result2->fetch(PDO::FETCH_NUM);
                $data.= "\n\n".$row2[1].";\n\n";

                for ($i = 0; $i < $num_fields; $i++){
										
                    while($row = $result->fetch(PDO::FETCH_NUM)){ 
					
                        $data.= 'INSERT INTO '.$table.' VALUES(';
                        for($j=0; $j<count($row); $j++) 
                        {
                            $row[$j] = addslashes($row[$j]); 
                            $row[$j] = str_replace("\n","\\n",$row[$j]);
                            if (isset($row[$j])) { $data.= '"'.$row[$j].'"' ; } else { $data.= '""'; }
                            if ($j<(count($row)-1)) { $data.= ','; }
                        }
                        $data.= ");\n";
                    }
                }
                $data.="\n\n";
            }

            $filename = 'backup/backup_'.time().'_'.$this->dbname.'.sql';
            $this->writeUTF8filename($filename,$data);
			
			return $filename;
        }

        private function writeUTF8filename($filenamename,$content){
            $f=fopen($filenamename,"w+"); 
            fwrite($f, pack("CCC",0xef,0xbb,0xbf)); 
            fwrite($f,$content); 
            fclose($f); 
        }

    } /*END OF CLASS*/
		
	//Backup do painel_acessos
	$painel_acessos = new MySql($_MDouglas['servidor'],$_MDouglas['painel_acessos'],$_MDouglas['usuario'], $_MDouglas['senha']);
    $backup_acessos =  $painel_acessos->backup_tables();
	
	//Backup do painel_geral
	$painel_geral = new MySql($_MDouglas['servidor'],$_MDouglas['painel_geral'],$_MDouglas['usuario'], $_MDouglas['senha']);
    $backup_geral = $painel_geral->backup_tables();
	
	//Backup do painel_user
	$painel_user = new MySql($_MDouglas['servidor'],$_MDouglas['painel_user'],$_MDouglas['usuario'], $_MDouglas['senha']);
    $backup_user = $painel_user->backup_tables();
	
	include("conexao.php");
	
	$HorarioInserir = time() + (3600 * $tempo);
	$SQLBa = "UPDATE backup SET
			horario = :horario";
	$SQLBa = $painel_geral->prepare($SQLBa);                                  
	$SQLBa->bindValue(':horario', $HorarioInserir); 
	$SQLBa->execute();
				
			$assunto = $_TRA['Backup']." - ".UrlAtual();
			$MensagemEmail = $_TRA['BackupAnexo'];
													
			if($EnviarStatus == "S"){
				$SQLSMS = "SELECT usuario FROM admin";
				$SQLSMS = $painel_user->prepare($SQLSMS);
				$SQLSMS->execute();
				while($LnSMS = $SQLSMS->fetch()){
					
					$VerificarVerEmail = VerificarVerEmail($LnSMS['usuario']);
					if( ($VerificarVerEmail != 1) && ($VerificarVerEmail != 2) ){
															
						$bloqueado = "N";
						$SQLUser = "SELECT servidor, exibicao, email, usuario, senha, SMTPSecure, Host, Port FROM email_adicionar WHERE CadUser = :CadUser AND bloqueado = :bloqueado";
						$SQLUser = $painel_geral->prepare($SQLUser);
						$SQLUser->bindParam(':CadUser', $LnSMS['usuario'], PDO::PARAM_STR);
						$SQLUser->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
						$SQLUser->execute();
						$Total = count($SQLUser->fetchAll());
															
							if($Total > 0){
								$SQLUser->execute();
								$LnUser = $SQLUser->fetch();
								$EnviarEmail = EnviarEmail($LnUser['SMTPSecure'], $LnUser['Host'], $LnUser['Port'], $LnUser['usuario'], $LnUser['senha'], $LnUser['email'], $LnUser['exibicao'], $LnStatusServer['email'], $assunto, $MensagemEmail, $backup_acessos, NULL, $backup_geral, $backup_user);
								@unlink($backup_acessos);
								@unlink($backup_geral);
								@unlink($backup_user);
							}
						}
					}
				}
	
	///////////////////////////////////////////////////////////
	///                 FINALIZA O BACKUP                   ///
	///////////////////////////////////////////////////////////	
	
	if(empty($SQLBa)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['Backuprcs'], "success", "index.php?p=backup");
	}

?>