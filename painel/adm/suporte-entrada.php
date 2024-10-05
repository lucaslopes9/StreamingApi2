<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$m = empty($_GET['m']) ? "" : $_GET['m'];
$id = (isset($_POST['id'])) ? $_POST['id'] : '';
$id = empty($id) ? $m : $id;
$UserReceptor = InfoUser(2);
$pastaGet = empty($_GET['a']) ? 1 : $_GET['a'];
$Pasta = empty($_POST['pasta']) ? $pastaGet : $_POST['pasta'];

$SQL = "SELECT * FROM suporte WHERE id = :id AND UserReceptor = :UserReceptor OR id = :id AND UserEmissor = :UserEmissor";
$SQL = $painel_geral->prepare($SQL);
$SQL->bindParam(':id', $id, PDO::PARAM_INT);
$SQL->bindParam(':UserReceptor', $UserReceptor, PDO::PARAM_STR);
$SQL->bindParam(':UserEmissor', $UserReceptor, PDO::PARAM_STR);
$SQL->execute();
$Ln = $SQL->fetch();
$UserEmissor = $Ln['UserEmissor'];
$Assunto = empty($Ln['Assunto']) ? "" : "Re: ".$Ln['Assunto']." ";
$Mensagem = empty($Ln['Mensagem']) ? "" : $Ln['Mensagem'];
$Anexo = empty($Ln['anexo']) ? "" : $Ln['anexo'];

if( ($Ln['UserReceptor'] == $UserReceptor) && ($Ln['LidaReceptor'] == "N") ){
		$LidaReceptor = "S";
		$SQL = "UPDATE suporte SET
			LidaReceptor = :LidaReceptor
            WHERE id = :id AND UserReceptor = :UserReceptor";
		$SQL = $painel_geral->prepare($SQL);
		$SQL->bindParam(':LidaReceptor', $LidaReceptor, PDO::PARAM_STR); 
		$SQL->bindParam(':id', $id, PDO::PARAM_INT);
		$SQL->bindParam(':UserReceptor', $UserReceptor, PDO::PARAM_STR); 
		$SQL->execute(); 
}
if( ($Ln['UserEmissor'] == $UserReceptor) && ($Ln['LidaEmissor'] == "N") ){
		$LidaEmissor = "S";
		$SQL = "UPDATE suporte SET
			LidaEmissor = :LidaEmissor
            WHERE id = :id AND UserEmissor = :UserEmissor";
		$SQL = $painel_geral->prepare($SQL);
		$SQL->bindParam(':LidaEmissor', $LidaEmissor, PDO::PARAM_STR); 
		$SQL->bindParam(':id', $id, PDO::PARAM_INT);
		$SQL->bindParam(':UserEmissor', $UserReceptor, PDO::PARAM_STR); 
		$SQL->execute();
}

$SQLEmis = "(SELECT email, foto FROM admin WHERE usuario = :usuario) UNION ALL (SELECT email, foto FROM rev WHERE usuario = :usuario) UNION ALL (SELECT email, foto FROM teste WHERE usuario = :usuario) UNION ALL (SELECT email, foto FROM usuario WHERE usuario = :usuario)";
$SQLEmis = $painel_user->prepare($SQLEmis);
$SQLEmis->bindParam(':usuario', $UserEmissor, PDO::PARAM_STR);
$SQLEmis->execute();
$LnEmis = $SQLEmis->fetch();
$FotoEmissor = empty($LnEmis['foto']) ? "" : $LnEmis['foto'];

$EmailEmissor = empty($LnEmis['email']) ? "" : "<small>".$LnEmis['email']."</small>";
$Foto = Foto($FotoEmissor);

//Resposta Anexo
$SQLResp = "SELECT * FROM suporteresp WHERE id_suporte = :id_suporte";
$SQLResp = $painel_geral->prepare($SQLResp);
$SQLResp->bindParam(':id_suporte', $id, PDO::PARAM_INT);
$SQLResp->execute();
$TotalResp = count($SQLResp->fetchAll());
?>

<div class="content-frame-body">
                        
                        <div class="panel panel-default">
                        
                            <div class="panel-heading">
                                <div class="pull-left">
                                    <h3 class="panel-title"><?php echo $UserEmissor." ".$EmailEmissor; ?></h3>
                                </div>

                                <?php
								$AcessoUser = InfoUser(3);
								if( ($AcessoUser == 1) || ($AcessoUser == 2) ){
									
								$SQLGrupo = "(SELECT grupo FROM usuario WHERE usuario = :usuario) UNION ALL (SELECT grupo FROM teste WHERE usuario = :usuario)";
								$SQLGrupo = $painel_user->prepare($SQLGrupo);
								$SQLGrupo->bindParam(':usuario', $UserEmissor, PDO::PARAM_INT);
								$SQLGrupo->execute();
								$LnGrupo = $SQLGrupo->fetch();
									
								if($LnGrupo['grupo'] == 3){
									$GrupoUser = "usuario";
								}
								else{
									$GrupoUser = "teste";
								}
								?>
                                <div class="pull-right">
                                    &nbsp;<a href="index.php?p=<?php echo $GrupoUser; ?>&user=<?php echo $UserEmissor; ?>" class="btn btn-warning"><span class="fa fa-pencil"></span></a>
								</div>
                               	<?php
								}

								if($Pasta == 4){
								?>
                                <div value="<?php echo $id; ?>" id="DeletarMensagemLixeira" class="pull-right">
                                    <button class="btn btn-default"><span class="fa fa-trash-o"></span></button>
								</div>
                                <?php	
								}
								else{
								?>
                                <div value="<?php echo $id; ?>" id="DeletarMensagem" class="pull-right">
                                	<button class="btn btn-default"><span class="fa fa-trash-o"></span></button>
                                </div>
                                <?php
								}
								?>
                            </div>
                            <div class="panel-body">
                                <h3><?php echo $Assunto; ?><small class="pull-right text-muted"><span class="fa fa-clock-o"></span> <?php echo DataSuporte2($Ln['data']); ?></small></h3>
                                <?php echo $Mensagem; ?>  
                            </div>
                        </div>
                        
                        <?php
						$SQLResp->execute();
						while($LnResp = $SQLResp->fetch()){
							$UserEmissorResp = $LnResp['UserEmissor'];
							
							$SQLEmisResp = "(SELECT email, foto FROM admin WHERE usuario = :usuario) UNION ALL (SELECT email, foto FROM rev WHERE usuario = :usuario) UNION ALL (SELECT email, foto FROM teste WHERE usuario = :usuario) UNION ALL (SELECT email, foto FROM usuario WHERE usuario = :usuario)";
							$SQLEmisResp = $painel_user->prepare($SQLEmisResp);
							$SQLEmisResp->bindParam(':usuario', $UserEmissorResp, PDO::PARAM_STR);
							$SQLEmisResp->execute();
							$LnEmisResp = $SQLEmisResp->fetch();
							$FotoEmissorResp = empty($LnEmisResp['foto']) ? "" : $LnEmisResp['foto'];
							$EmailEmissorResp = empty($LnEmisResp['email']) ? "" : "<small>".$LnEmisResp['email']."</small>";
										
							$FotoResp = Foto($FotoEmissorResp);
							$MensagemResp = empty($LnResp['mensagem']) ? "" : $LnResp['mensagem'];
						?>
                        <div class="panel panel-default">
                            <div class="panel-heading">
                                <div class="pull-left">
                                    <h3 class="panel-title"><?php echo $UserEmissorResp." ".$EmailEmissorResp; ?></h3>
                                </div>
                            </div>
                            <div class="panel-body">
                                <h3><small class="pull-right text-muted"><span class="fa fa-clock-o"></span> <?php echo DataSuporte2($LnResp['data']); ?></small></h3>
                                <?php echo $MensagemResp; ?>  
                            </div>
                        </div>
                        <?php
						}
						?>

                        
                        <div class="panel panel-default">
                            <div class="panel-body">
                                <form role="form" method="post" enctype="multipart/form-data" id="FormAnexo" action="javascript:MDouglasMS();">   
                                <div class="ResponderMensagem form-group push-up-20">
                                    <label><?php echo $_TRA['rr']; ?></label>
                                    <textarea class="form-control summernote_lite" name="mensagem" id="mensagem" rows="3" placeholder="<?php echo $_TRA['cqpr']; ?>"></textarea>
                                </div>
                        
                                </form>
                            </div>
                            
                            <div class="ResponderPost panel-footer">
                            </div>
                        </div>
                        
                    </div>
                 
                <?php
				if(empty($m)){
				?>
                <script type="text/javascript" src="js/plugins/summernote/summernote<?php echo Idioma(2); ?>.js"></script>
                <script type="text/javascript" src="js/plugins/bootstrap/bootstrap-file-input.js"></script>
                <script type='text/javascript' src='js/plugins.js'></script>
                <?php
				}
				?>
                
                <script type='text/javascript'> 
                $(function(){  
 					$(".panel-heading #DeletarMensagem").on("click",function(){
				
						var SelectBox = $(this).attr("value");
																
						$.post('AtualizarLixeiraSupp.php', {SelectBox: SelectBox}, function(resposta) {
							$("#StatusGeral").html(resposta);
						});
						
					});
				});
				
				$(function(){  
 					$(".panel-heading #DeletarMensagemLixeira").on("click",function(){
				
						var SelectBox = $(this).attr("value");
																
						$.post('AtualizarLixeiraSuppLixeira.php', {SelectBox: SelectBox}, function(resposta) {
							$("#StatusGeral").html(resposta);
						});
						
					});
				});
				
				if($(".summernote_lite").length > 0){
        			$(".summernote_lite").on("focus",function(){
           	 			$(".ResponderPost").html('<button class="btn btn-success pull-right"><span class="fa fa-mail-reply"></span> <?php echo $_TRA['Responder']; ?></button>');
						$( ".FormAnexar" ).show();
        			});                
        		}
				
				$(function(){  
 					$(".ResponderPost").on("click",function(){
						
						pageLoadingFrame("show");
						
						var formData = new FormData($("#FormAnexo")[0]); 
						formData.append( 'mensagem', $('#FormAnexo textarea[name="mensagem"]').code() );
						formData.append( 'id_suporte', '<?php echo $id; ?>');
						formData.append( 'pasta', '<?php echo $Pasta; ?>');
						
  						$.ajax({
    						url: 'UploadAnexo.php',
     						type: 'POST',
     						data: formData,
     						async: false,
     						cache: false,
     						contentType: false,
     						enctype: 'multipart/form-data',
    						processData: false,
     						success: function (response) {
								setTimeout(function(){
                       				pageLoadingFrame("hide");
									$("#StatusGeral").html(response);
              					},1000);
     						}
   						});
						
					});
				});
				
			</script>

<?php
}else{
	echo Redirecionar('login.php');
}	
?>