<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('StatusLogs');
$VerificarAcesso = VerificarAcesso('status', $ColunaAcesso);
$StatusOnline = $VerificarAcesso[0];

if($StatusOnline == 'S'){

$caduser = empty($_POST['caduser']) ? '' : $_POST['caduser'];
$rev = empty($_POST['rev']) ? '' : $_POST['rev'];
$status = empty($_POST['status']) ? '' : $_POST['status'];
$perfil = empty($_POST['perfil']) ? '' : $_POST['perfil'];

if(empty($caduser)){
	echo MensagemAlerta($_TRA['erro'], $_TRA['sur'], "danger");
}
elseif(empty($rev)){
	echo MensagemAlerta($_TRA['erro'], $_TRA['edr'], "danger");
}
elseif(empty($status)){
	echo MensagemAlerta($_TRA['erro'], $_TRA['sus'], "danger");
}
elseif(empty($perfil)){
	echo MensagemAlerta($_TRA['erro'], $_TRA['sup'], "danger");
}
else{
	
	$VerificarStatusLogs = VerificarStatusLogs($caduser, $rev, $perfil, $status);
?>

<div class="table-responsive">
                               <table id="Tabela" class="table datatable">
                               <thead>
                               		<tr>
                                    	<th><?php echo $_TRA['Status']; ?></th>
                                        <th><?php echo $_TRA['nome']; ?></th>
                                        <th><?php echo $_TRA['Usuario']; ?></th>
                                        <th><?php echo $_TRA['cpor']; ?></th>
                                        <th><?php echo $_TRA['ECM']; ?></th>
                                        <th><?php echo $_TRA['Time']; ?></th>
                                        <th><?php echo $_TRA['IV']; ?></th>
                                        <th><?php echo $_TRA['Flags']; ?></th>
                                        <th><?php echo $_TRA['ip']; ?></th>
                                        <th><?php echo $_TRA['Perfil']; ?></th>
                                        <th><?php echo $_TRA['Canal']; ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                        <?php
									
									for($i=0; $i<count($VerificarStatusLogs); $i++){
										
									$PerfilAtual = "[".$VerificarStatusLogs[$i][4]."]";
									$perfil = SelecionarPerfil($PerfilAtual);
									
									$SQLUser = "SELECT CadUser, nome FROM usuario WHERE usuario = :usuario";
									$SQLUser = $painel_user->prepare($SQLUser);
									$SQLUser->bindParam(':usuario', $VerificarStatusLogs[$i][0], PDO::PARAM_STR);
									$SQLUser->execute();
									$LnUser = $SQLUser->fetch();
									
										if($VerificarStatusLogs[$i][3] == "false"){
											$status = "<span class=\"pointer label label-warning\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Ocioso']."\">".$_TRA['Ocioso']."</span>";
										}
										else{
											$status = "<span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Online']."\">".$_TRA['Online']."</span>";
										}
										
									echo "	
                                        <tr>
											<td>".$status."</td>
											<td>".$LnUser['nome']."</td>
											<td>".$VerificarStatusLogs[$i][0]."</td>
											<td>".$LnUser['CadUser']."</td>
											<td>".$VerificarStatusLogs[$i][7]."</td>
											<td>".$VerificarStatusLogs[$i][6]."</td>
											<td>".$VerificarStatusLogs[$i][1]."</td>
											<td>".$VerificarStatusLogs[$i][8]."</td>
											<td><span id=\"StatusIP".$i."\">".$VerificarStatusLogs[$i][2]."&nbsp;<a class=\"label label-info\" Onclick=\"InfoIP('".$VerificarStatusLogs[$i][2]."', '".$VerificarStatusLogs[$i][2]."', '#StatusIP".$i."')\"><i class=\"fa fa-exchange\"></i></a>&nbsp;</span></td>										<td>".$perfil."</td>
											<td>".$VerificarStatusLogs[$i][5]."</td>
                                       	    ";
											
									
								 	echo "</tr>";
									}
								  
										?>
										
                                            </tbody>
                                        </table>
                                    </div>
                                    
        <script type="text/javascript" src="js/plugins/datatables/jquery.dataTables.min.js"></script>
        <script type="text/javascript" src="js/DataTables<?php echo Idioma(2); ?>.js"></script>  
                    
        <script type="text/javascript" src="js/plugins.js"></script>
        
        <script type='text/javascript'> 
		function InfoIP(ip, usuario, div){
			
				$(div).html("<center><img src=\"img/fileinput/loading.gif\"></center>");
			
				$.post('InfoIP.php', {ip: ip, usuario: usuario}, function(resposta) {
				$(div).html('');
				$(div).html(resposta.trim());
				});
				
		}
		</script>

	
<?php
}
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}
?>