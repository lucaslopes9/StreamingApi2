<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('StatusFalhado');
$VerificarAcesso = VerificarAcesso('status', $ColunaAcesso);
$StatusOnline = $VerificarAcesso[0];

if($StatusOnline == 'S'){

$caduser = empty($_POST['caduser']) ? '' : $_POST['caduser'];
$rev = empty($_POST['rev']) ? '' : $_POST['rev'];

if(empty($caduser)){
	echo MensagemAlerta($_TRA['erro'], $_TRA['sur'], "danger");
}
elseif(empty($rev)){
	echo MensagemAlerta($_TRA['erro'], $_TRA['edr'], "danger");
}
else{
	
	$VerificarStatusFalhado = VerificarStatusFalhado($caduser, $rev);
?>

<div class="table-responsive">
                               <table id="Tabela" class="table datatable">
                               <thead>
                               		<tr>
                                        <th><?php echo $_TRA['nome']; ?></th>
                                        <th><?php echo $_TRA['Usuario']; ?></th>
                                        <th><?php echo $_TRA['cpor']; ?></th>
                                        <th><?php echo $_TRA['Contexto']; ?></th>
                                        <th><?php echo $_TRA['uf']; ?></th>
                                        <th><?php echo $_TRA['pf']; ?></th>
                                        <th><?php echo $_TRA['tdf']; ?></th>
                                        <th><?php echo $_TRA['ip']; ?></th>
                                        <th><?php echo $_TRA['motivo']; ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                        <?php
									
									for($i=0; $i<count($VerificarStatusFalhado); $i++){
									
									$SQLUser = "SELECT CadUser, nome FROM usuario WHERE usuario = :usuario";
									$SQLUser = $painel_user->prepare($SQLUser);
									$SQLUser->bindParam(':usuario', $VerificarStatusFalhado[$i][0], PDO::PARAM_STR);
									$SQLUser->execute();
									$LnUser = $SQLUser->fetch();
										
									echo "	
                                        <tr>
											<td>".$LnUser['nome']."</td>
											<td>".$VerificarStatusFalhado[$i][0]."</td>
											<td>".$LnUser['CadUser']."</td>
											<td>".$VerificarStatusFalhado[$i][1]."</td>
											<td>".OrganizarHora($VerificarStatusFalhado[$i][2])."</td>
											<td>".OrganizarHora($VerificarStatusFalhado[$i][3])."</td>
											<td>".$VerificarStatusFalhado[$i][4]."</td>
											<td><span id=\"StatusIP".$i."\">".$VerificarStatusFalhado[$i][5]."&nbsp;<a class=\"label label-info\" Onclick=\"InfoIP('".$VerificarStatusFalhado[$i][5]."', '".$VerificarStatusFalhado[$i][0]."', '#StatusIP".$i."')\"><i class=\"fa fa-exchange\"></i></a>&nbsp;</span></td>
											<td>".$VerificarStatusFalhado[$i][6]."</td>
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