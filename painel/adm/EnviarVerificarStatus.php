<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$VerificarStatusUsuario = array_filter(VerificarStatusUsuario());
	
	
if(!empty($VerificarStatusUsuario)){
echo "
                                        <table class=\"table table-striped\">
                                            <thead>
                                                <tr>
                                                    <th>".$_TRA['Status']."</th>
                                                    <th>".$_TRA['Servidor']."</th>
                                                    <th>".$_TRA['Canal']."</th>
                                                    <th>".$_TRA['ip']."</th>
                                                </tr>
                                            </thead>
                                            <tbody>";
											
											for($i = 0; $i < count($VerificarStatusUsuario); $i++){
												
												$perfil = "[".$VerificarStatusUsuario[$i][2]."]";
												
												$bloqueado = "N";
												$SQLPerfil = "SELECT painel FROM perfil WHERE valorcsp = :valorcsp AND bloqueado = :bloqueado";
												$SQLPerfil = $painel_geral->prepare($SQLPerfil);
												$SQLPerfil->bindParam(':valorcsp', $perfil, PDO::PARAM_STR);
												$SQLPerfil->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
												$SQLPerfil->execute();
												$LnPerfil = $SQLPerfil->fetch();
												$painel = $LnPerfil['painel'];
												
												$SQLPainel = "SELECT nome FROM painel WHERE id = :id";
												$SQLPainel = $painel_geral->prepare($SQLPainel);
												$SQLPainel->bindParam(':id', $painel, PDO::PARAM_STR);
												$SQLPainel->execute();
												$LnPainel = $SQLPainel->fetch();
												
												if($VerificarStatusUsuario[$i][0] == "false"){
													$status = "<span class=\"pointer label label-warning\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Ocioso']."\">".$_TRA['Ocioso']."</span>";
												}
												else{
													$status = "<span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Online']."\">".$_TRA['Online']."</span>";
												}
												
												echo "
                                                <tr>
                                                    <td>".$status."</td>
                                                    <td>".$LnPainel['nome']."</td>
                                                    <td>".$VerificarStatusUsuario[$i][3]."</td>
                                                    <td>".$VerificarStatusUsuario[$i][1]."</td>
                                                </tr>
												";
											}
												
                                            echo "</tbody>
                                        </table>
				";
}
else{
	
	echo "<center>".$_TRA['nce']."</center>";
}
	
	
	
	
	
	
}else{
	echo Redirecionar('login.php');
}	
?>