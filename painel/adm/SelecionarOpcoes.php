<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('AdminVisualizar', 'AdminBloquear', 'AdminDesativar', 'AdminExcluir');
$VerificarAcesso = VerificarAcesso('admin', $ColunaAdmin);

$AdminVisualizar = $VerificarAcesso[0];
$AdminBloquear = $VerificarAcesso[1];
$AdminDesativar = $VerificarAcesso[2];
$AdminExcluir = $VerificarAcesso[3];
 
if($AdminVisualizar == 'S'){
?>

<script type='text/javascript'>
$(function(){  
 			$("a.ExibirOpcoes").click(function() { 
			
			var status = $(this).attr("status"); 
			
			if(status == 'arvore'){
				statusE = '<?php echo $_TRA['aa']; ?>';
			}
			else if(status == 'bloquear'){
		
				statusE = '<?php echo $_TRA['bloquear']; ?>';
				var fa = 'fa fa-lock'; 
				var tipo = 'danger';
			}
			else if(status == 'desbloquear'){
				statusE = '<?php echo $_TRA['desbloquear']; ?>';
				var fa = 'fa fa-unlock-alt'; 
				var tipo = 'success';
			}
			else if(status == 'ativar'){
				statusE = '<?php echo $_TRA['ativar']; ?>';
				var fa = 'fa fa-check'; 
				var tipo = 'success';
			}
			else if(status == 'desativar'){
				statusE = '<?php echo $_TRA['desativar']; ?>';
				var fa = 'fa fa-times'; 
				var tipo = 'danger';
			}
			else if(status == 'excluir'){
				statusE = '<?php echo $_TRA['excluir']; ?>';
				var fa = 'fa fa-trash-o'; 
				var tipo = 'danger';
			}
			else{
				statusE = '<?php echo $_TRA['opcoes']; ?>';
				var fa = 'fa fa-gear'; 
				var tipo = 'danger';
			}

			$("#StatusEG").html(statusE);
						
			camposMarcados = new Array();
			$("input[type=checkbox][name='SelectUser[]']:checked").each(function(){
    		camposMarcados.push($(this).val());
			});
			
			if(status == 'arvore'){
					
					panel_refresh($(".page-container"));
				
					$.post('ScriptModalAlterarArvoreAdmin.php', {camposMarcados: camposMarcados}, function(resposta) {
						
						setTimeout(panel_refresh($(".page-container")),500);
						
						$("#StatusGeral").html('');
						$("#StatusGeral").html(resposta);
					});
			}
			else{
					var titulo = statusE + '?';
					var texto = 'Tem certeza que deseja '+statusE+'?';
					var url = 'EnviarOpcoesAdmin';
					$.post('ScriptAlertaJS2.php', {camposMarcados: camposMarcados, status: status, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
						$("#StatusGeral").html('');
						$("#StatusGeral").html(resposta);
					});
				}
			});
		});
</script>

<button type="button" class="btn btn-default"><span id="StatusEG"><?php echo $_TRA['opcoes']; ?></span></button>
<button type="button" class="btn btn-default dropdown-toggle" data-toggle="dropdown" aria-expanded="false"><span class="caret"></span></button>
<ul class="dropdown-menu" role="menu">

<?php
echo "<li><a status=\"arvore\" class=\"ExibirOpcoes pointer\">".$_TRA['aa']."</a></li>";

if($AdminBloquear == "S"){
echo "<li><a status=\"bloquear\" class=\"ExibirOpcoes pointer\">".$_TRA['bloquear']."</a></li>
<li><a status=\"desbloquear\" class=\"ExibirOpcoes pointer\">".$_TRA['desbloquear']."</a></li>";
}

if($AdminDesativar == "S"){
echo "<li><a status=\"ativar\" class=\"ExibirOpcoes pointer\">".$_TRA['ativar']."</a></li>
<li><a status=\"desativar\" class=\"ExibirOpcoes pointer\">".$_TRA['desativar']."</a></li>";
}

if($AdminExcluir == "S"){
echo "<li><a status=\"excluir\" class=\"ExibirOpcoes pointer\">".$_TRA['excluir']."</a></li>";
}
?>
</ul>
&nbsp;&nbsp; 

<?php
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>